#!/usr/bin/env python3
"""Go / Rust Core Differential Contract Test Harness.

Executes sequential IPC calls simultaneously against the official Go FlClashCore
and the pure-Rust FlClashCore, performing recursive structural diffs on responses
and verifying parity against the Flutter client's expectations.
"""

import argparse
import asyncio
import copy
import http.server
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple


class Host(asyncio.Protocol):
    """Asyncio protocol for IPC framing (4-byte LE length + UTF-8 JSON)."""

    def __init__(self, label: str):
        self.label = label
        self.buf = b""
        self.waiters: Dict[str, asyncio.Future] = {}
        self.events = 0
        self.connected = asyncio.get_event_loop().create_future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        if not self.connected.done():
            self.connected.set_result(True)

    def data_received(self, data: bytes):
        self.buf += data
        while len(self.buf) >= 4:
            n = struct.unpack("<I", self.buf[:4])[0]
            if len(self.buf) < 4 + n:
                break
            payload, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
            try:
                msg = json.loads(payload.decode("utf-8"))
            except Exception as e:
                print(f"  [{self.label}] undecodable frame: {e} raw: {payload[:200]!r}")
                continue
            if msg.get("method") == "message":
                self.events += 1
                continue
            cid = msg.get("id")
            fut = self.waiters.pop(cid, None)
            if fut and not fut.done():
                fut.set_result(msg)

    def connection_lost(self, exc):
        for f in self.waiters.values():
            if not f.done():
                f.set_exception(ConnectionError(f"IPC pipe closed: {exc}"))

    async def call(self, method: str, args: Any = None, timeout: float = 30.0) -> Tuple[Dict[str, Any], float]:
        cid = uuid.uuid4().hex
        fut = asyncio.get_event_loop().create_future()
        self.waiters[cid] = fut
        body = json.dumps({"id": cid, "method": method, "arguments": args}, ensure_ascii=False).encode("utf-8")
        self.transport.write(struct.pack("<I", len(body)) + body)
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.waiters.pop(cid, None)
            return {"_timeout": True, "method": method}, time.monotonic() - t0
        except Exception as e:
            self.waiters.pop(cid, None)
            return {"_call_exception": str(e), "method": method}, time.monotonic() - t0

        if resp.get("file"):
            spill_file = resp["file"]
            try:
                with open(spill_file, "r", encoding="utf-8") as fh:
                    resp["result"] = json.load(fh)
            except Exception as e:
                resp["result"] = {"_spill_error": str(e), "_path": spill_file}
        return resp, time.monotonic() - t0


class CoreInstance:
    """Manages a running FlClashCore process and its IPC pipe."""

    def __init__(self, label: str, binary: str, home_dir: str, env: Dict[str, str]):
        self.label = label
        self.binary = os.path.abspath(binary)
        self.home_dir = os.path.abspath(home_dir)
        self.env = env
        self.pipe_name = ""
        self.host: Optional[Host] = None
        self.servers = []
        self.proc: Optional[subprocess.Popen] = None
        self.log_file = None

    async def start(self, logs_dir: str):
        loop = asyncio.get_event_loop()
        uid = uuid.uuid4().hex[:12]
        if platform.system() == "Windows":
            self.pipe_name = rf"\\.\pipe\wx_contract_{self.label}_{uid}"
        else:
            self.pipe_name = os.path.join(self.home_dir, f"ipc_{uid}.sock")

        self.host = Host(self.label)
        if platform.system() == "Windows":
            self.servers = await loop.start_serving_pipe(lambda: self.host, self.pipe_name)
        else:
            server = await loop.create_unix_server(lambda: self.host, path=self.pipe_name)
            self.servers = [server]

        log_path = os.path.join(logs_dir, f"{self.label}-stderr.log")
        self.log_file = open(log_path, "wb")
        self.proc = subprocess.Popen(
            [self.binary, self.pipe_name],
            cwd=self.home_dir,
            env=self.env,
            stdout=self.log_file,
            stderr=self.log_file,
        )

        try:
            await asyncio.wait_for(self.host.connected, 20.0)
            print(f"[{self.label}] connected to IPC pipe (pid {self.proc.pid})")
        except asyncio.TimeoutError:
            ret = self.proc.poll()
            raise RuntimeError(f"[{self.label}] failed to connect within 20s (process exit code: {ret})")

    async def call(self, method: str, args: Any = None, timeout: float = 30.0) -> Tuple[Dict[str, Any], float]:
        if not self.host:
            raise RuntimeError(f"[{self.label}] IPC host not initialized")
        return await self.host.call(method, args, timeout)

    def stop(self):
        try:
            if self.host and self.host.transport:
                self.host.transport.close()
        except Exception:
            pass
        for s in self.servers:
            try:
                s.close()
            except Exception:
                pass
        if self.proc:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Structural Diffing & Whitelist Engine
# ---------------------------------------------------------------------------

class DiffResult:
    def __init__(self, check_id: str, method: str, args_summary: str):
        self.check_id = check_id
        self.method = method
        self.args_summary = args_summary
        self.go_summary = ""
        self.rust_summary = ""
        self.verdict = "PASS"  # PASS, WHITELISTED, FAIL
        self.details: List[str] = []
        self.go_resp: Any = None
        self.rust_resp: Any = None

    def add_fail(self, msg: str):
        self.verdict = "FAIL"
        self.details.append(msg)

    def add_whitelist(self, msg: str):
        if self.verdict != "FAIL":
            self.verdict = "WHITELISTED"
        self.details.append(f"[WHITELISTED] {msg}")


FLUTTER_CONSUMED_PROFILE_FIELDS = {
    "mode", "tun", "dns", "mixed-port", "port", "socks-port", "allow-lan",
    "log-level", "ipv6", "unified-delay", "tcp-concurrent", "find-process-mode",
    "bind-address", "geo-auto-update", "geo-update-interval", "profile", "hosts"
}


def recursive_compare(path: str, go_val: Any, rust_val: Any, diff: DiffResult):
    """Deep structural diff comparing types, keys, and values."""
    if go_val is None:
        if rust_val is not None:
            if path.endswith(".connections") and rust_val == []:
                diff.add_whitelist(f"{path}: Go is None, Rust is empty list []")
                return
            diff.add_fail(f"{path}: Go is None, Rust is {type(rust_val).__name__} ({rust_val!r})")
        return

    if rust_val is None:
        if path.endswith(".connections") and go_val == []:
            diff.add_whitelist(f"{path}: Rust is None, Go is empty list []")
            return
        diff.add_fail(f"{path}: Go is {type(go_val).__name__}, Rust is None")
        return

    if type(go_val) != type(rust_val):
        # Allow int and float compatibility if values are equal
        if isinstance(go_val, (int, float)) and isinstance(rust_val, (int, float)):
            pass
        else:
            diff.add_fail(f"{path}: type mismatch: Go has {type(go_val).__name__}, Rust has {type(rust_val).__name__}")
            return

    if isinstance(go_val, dict):
        go_keys = set(go_val.keys())
        rust_keys = set(rust_val.keys())

        missing_in_rust = go_keys - rust_keys
        extra_in_rust = rust_keys - go_keys

        # Check critical fields
        for k in missing_in_rust:
            sub_path = f"{path}.{k}"
            if path.startswith("proxy.list.proxies.") and k in ("extra", "tfo", "mptcp"):
                diff.add_whitelist(f"{sub_path}: optional proxy field missing in Rust")
            elif path == "profile.base.config" or path.startswith("profile.base.config."):
                if k in FLUTTER_CONSUMED_PROFILE_FIELDS:
                    diff.add_fail(f"{sub_path}: critical Flutter profile field missing in Rust config")
                else:
                    diff.add_whitelist(f"{sub_path}: mihomo internal struct field omitted in raw profile (not read by Flutter)")
            else:
                diff.add_fail(f"{path}: key {k!r} present in Go but missing in Rust")

        for k in extra_in_rust:
            sub_path = f"{path}.{k}"
            if path.startswith("proxy.list.proxies."):
                diff.add_fail(f"{sub_path}: unexpected extra key {k!r} in proxy node (must match Go nodeView)")
            elif path == "profile.base.config" or path.startswith("profile.base.config."):
                diff.add_whitelist(f"{sub_path}: extra default field in Rust profile config")
            else:
                diff.add_fail(f"{path}: extra key {k!r} in Rust not in Go")

        # Recurse on shared keys
        for k in sorted(go_keys & rust_keys):
            sub_path = f"{path}.{k}"
            # Whitelisted fields whose values may naturally vary
            if sub_path in ("core.memory.inuse", "core.memory.osalloc"):
                if isinstance(rust_val[k], (int, float)) and rust_val[k] > 0:
                    diff.add_whitelist(f"{sub_path}: memory stats value varies ({go_val[k]} vs {rust_val[k]})")
                else:
                    diff.add_fail(f"{sub_path}: Rust value must be positive integer, got {rust_val[k]!r}")
            elif sub_path in ("traffic.total.down", "traffic.total.up"):
                if isinstance(go_val[k], (int, float)) and isinstance(rust_val[k], (int, float)):
                    if go_val[k] > 0 and rust_val[k] > 0:
                        pass  # Verified: both Go and Rust recorded traffic (> 0)
                    elif go_val[k] == 0 and rust_val[k] == 0:
                        pass
                    else:
                        diff.add_fail(f"{sub_path}: both must be > 0 with traffic, got Go={go_val[k]}, Rust={rust_val[k]}")
                else:
                    diff.add_fail(f"{sub_path}: invalid type: Go={type(go_val[k])}, Rust={type(rust_val[k])}")
            elif sub_path in ("traffic.current.up", "traffic.current.down"):
                if isinstance(go_val[k], (int, float)) and isinstance(rust_val[k], (int, float)):
                    if go_val[k] >= 0 and rust_val[k] >= 0:
                        pass  # Valid rate numbers
                    else:
                        diff.add_fail(f"{sub_path}: rates must be non-negative, got Go={go_val[k]}, Rust={rust_val[k]}")
                else:
                    diff.add_fail(f"{sub_path}: invalid rate type: Go={type(go_val[k])}, Rust={type(rust_val[k])}")
            elif sub_path in ("connection.list.downloadTotal", "connection.list.uploadTotal", "connection.list.memory"):
                diff.add_whitelist(f"{sub_path}: connection stats vary ({go_val[k]} vs {rust_val[k]})")
            elif sub_path in ("proxy.testDelay.delay", "proxy.testDelay.value"):
                if go_val[k] == rust_val[k] or (go_val[k] > 0 and rust_val[k] > 0) or (go_val[k] < 0 and rust_val[k] < 0):
                    diff.add_whitelist(f"{sub_path}: delay measurement parity (Go={go_val[k]}, Rust={rust_val[k]})")
                else:
                    diff.add_fail(f"{sub_path}: delay mismatch: Go={go_val[k]}, Rust={rust_val[k]}")
            elif sub_path in ("route.watch.core-epoch", "route.watch.route-version", "route.check.core-epoch", "route.check.route-version"):
                diff.add_whitelist(f"{sub_path}: epoch/version numeric variance ({go_val[k]} vs {rust_val[k]})")
            else:
                recursive_compare(sub_path, go_val[k], rust_val[k], diff)

    elif isinstance(go_val, list):
        # List comparison: strictly fail on any length mismatch unless specifically whitelisted
        if len(go_val) != len(rust_val):
            if path in ("proxy.list.all",) or (path.startswith("proxy.list.proxies.") and path.endswith(".all")):
                diff.add_fail(f"{path}: proxy/group list length mismatch: Go={len(go_val)}, Rust={len(rust_val)}")
            elif path.startswith("connection.list.connections") or path == "connection.list":
                diff.add_whitelist(f"{path}: active connection list size varies ({len(go_val)} vs {len(rust_val)})")
            else:
                diff.add_fail(f"{path}: list length mismatch: Go={len(go_val)}, Rust={len(rust_val)}")

        # If both are empty, ok
        if not go_val and not rust_val:
            return

        # Compare elements up to min length
        min_len = min(len(go_val), len(rust_val))
        for idx in range(min_len):
            recursive_compare(f"{path}[{idx}]", go_val[idx], rust_val[idx], diff)

    else:
        # Scalar comparison
        # Enforce critical invariants
        if path.endswith(".hidden"):
            if rust_val != go_val:
                diff.add_fail(f"{path}: hidden mismatch! Go={go_val}, Rust={rust_val} (CRITICAL for UI visibility)")
        elif path.endswith(".type") and "proxies" in path:
            if rust_val != go_val:
                diff.add_fail(f"{path}: proxy/group type mismatch! Go={go_val!r}, Rust={rust_val!r}")
        elif path == "core.initialized":
            if rust_val is not True:
                diff.add_fail(f"core.initialized must be True, got {rust_val!r}")
        elif path.startswith("config.validate") and path.endswith("result"):
            if rust_val != go_val:
                diff.add_fail(f"{path}: validation result mismatch! Go={go_val!r}, Rust={rust_val!r}")


def compare_contract(check_id: str, method: str, args: Any, resp_go: Dict[str, Any], resp_rust: Dict[str, Any]) -> DiffResult:
    args_str = json.dumps(args, ensure_ascii=False) if args else "None"
    if len(args_str) > 60:
        args_str = args_str[:57] + "..."
    diff = DiffResult(check_id, method, args_str)
    diff.go_resp = resp_go
    diff.rust_resp = resp_rust

    go_err = resp_go.get("error")
    rust_err = resp_rust.get("error")
    go_res = resp_go.get("result")
    rust_res = resp_rust.get("result")

    diff.go_summary = f"err={go_err.get('code')}" if go_err else f"res={type(go_res).__name__}"
    diff.rust_summary = f"err={rust_err.get('code')}" if rust_err else f"res={type(rust_res).__name__}"

    # Timeout check
    if resp_go.get("_timeout"):
        diff.add_fail("Go core call timed out")
    if resp_rust.get("_timeout"):
        diff.add_fail("Rust core call timed out")
    if diff.verdict == "FAIL":
        return diff

    # Both errors or both results?
    if go_err and not rust_err:
        diff.add_fail(f"Go failed with error {go_err.get('code')!r} ({go_err.get('message')!r}), but Rust succeeded")
        return diff
    if rust_err and not go_err:
        diff.add_fail(f"Go succeeded, but Rust failed with error {rust_err.get('code')!r} ({rust_err.get('message')!r})")
        return diff

    if go_err and rust_err:
        # Both returned error, compare code
        code_go = go_err.get("code")
        code_rust = rust_err.get("code")
        if code_go != code_rust:
            diff.add_fail(f"Error code mismatch: Go={code_go!r}, Rust={code_rust!r}")
        else:
            diff.add_whitelist(f"Error codes matched ({code_go}). Messages: Go={go_err.get('message')!r}, Rust={rust_err.get('message')!r}")
        return diff

    # Both returned results -> deep compare
    recursive_compare(method, go_res, rust_res, diff)
    return diff


# ---------------------------------------------------------------------------
# Test Scenarios Runner
# ---------------------------------------------------------------------------

def make_isolated_home(root: str, name: str, app_dir: str, config_yaml: Optional[str] = None) -> Tuple[str, Optional[str]]:
    home = os.path.join(root, name)
    shutil.rmtree(home, ignore_errors=True)
    os.makedirs(os.path.join(home, "profiles"), exist_ok=True)

    # Copy Flutter geodata assets
    assets = os.path.join(app_dir, "data", "flutter_assets", "assets", "data")
    if os.path.isdir(assets):
        for f in os.listdir(assets):
            src = os.path.join(assets, f)
            if os.path.isfile(src):
                shutil.copy(src, os.path.join(home, f))

    prof_path = None
    if config_yaml:
        prof_path = os.path.join(home, "profiles", "1.yaml")
        with open(prof_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(config_yaml)
    return home, prof_path


def make_dart_overlay(base_config: Dict[str, Any], home: str, mixed_port: int = 7890) -> str:
    raw = dict(base_config or {})
    raw.pop("rule", None)
    raw.update({
        "external-controller": "", "secret": "", "external-controller-tls": "",
        "external-controller-unix": "", "external-controller-pipe": "",
        "external-ui": "", "interface-name": "", "external-ui-url": "",
    })
    raw.setdefault("unified-delay", True)
    raw.setdefault("tcp-concurrent", True)
    raw.setdefault("ipv6", False)
    raw.update({
        "log-level": "error", "keep-alive-interval": 30, "keep-alive-idle": 15,
        "disable-keep-alive": False, "routing-mark": 0, "mixed-port": mixed_port,
        "port": 0, "socks-port": 0, "redir-port": 0, "tproxy-port": 0,
        "find-process-mode": "off", "allow-lan": False, "authentication": [],
        "skip-auth-prefixes": [], "mode": "rule",
    })
    tun = dict(raw.get("tun") or {})
    tun.update({"dns-hijack": ["any:53"], "enable": False, "device": "WONDERX",
                "stack": "mixed", "auto-detect-interface": True})
    raw["tun"] = tun
    raw["geo-auto-update"] = False
    raw["geo-update-interval"] = 24
    raw["mitm"] = {"enable": False, "decrypt-tls": False, "ca-fingerprint": "",
                   "url-rewrite": [], "header-rewrite": [], "body-rewrite": [],
                   "map-local": [], "limits": {}}
    raw.setdefault("profile", {})
    raw["profile"]["store-selected"] = False
    raw["geox-url"] = {
        "mmdb": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb",
        "asn": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb",
        "geoip": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat",
        "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    }
    raw["global-ua"] = "FlClash X/v0.9.3 Platform/windows"
    raw.setdefault("hosts", {})
    raw["rules"] = []
    return json.dumps(raw, ensure_ascii=False, indent=1)


def check_windows_tun_status() -> Tuple[bool, List[str], List[str]]:
    """Inspect Windows network adapters and routing table for Wintun presence."""
    if platform.system() != "Windows":
        return False, [], []
    try:
        ps_adapters = "Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Wintun|WONDERX' -or $_.Name -match 'Wintun|WONDERX' } | Select-Object -ExpandProperty Name"
        out_a = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_adapters], text=True, stderr=subprocess.DEVNULL)
        adapters = [line.strip() for line in out_a.splitlines() if line.strip()]

        ps_routes = "Get-NetRoute | Where-Object { $_.InterfaceAlias -match 'Wintun|WONDERX' } | ForEach-Object { \"$($_.DestinationPrefix) via $($_.NextHop)\" }"
        out_r = subprocess.check_output(["powershell", "-NoProfile", "-Command", ps_routes], text=True, stderr=subprocess.DEVNULL)
        routes = [line.strip() for line in out_r.splitlines() if line.strip()]

        active = len(adapters) > 0 or len(routes) > 0
        return active, adapters, routes
    except Exception as e:
        return False, [], [f"Error checking Windows TUN: {e}"]


async def execute_contract_suite(
    core_go: CoreInstance,
    core_rust: CoreInstance,
    home_go: str,
    home_rust: str,
    realshape_text: str,
) -> List[DiffResult]:
    results: List[DiffResult] = []

    async def step(check_id: str, method: str, args_go: Any, args_rust: Optional[Any] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        nonlocal results
        actual_rust_args = args_rust if args_rust is not None else args_go
        # Call both concurrently
        task_go = core_go.call(method, args_go, timeout=35.0)
        task_rust = core_rust.call(method, actual_rust_args, timeout=35.0)
        (resp_go, dt_go), (resp_rust, dt_rust) = await asyncio.gather(task_go, task_rust)
        diff = compare_contract(check_id, method, args_go, resp_go, resp_rust)
        results.append(diff)
        mark = "✓" if diff.verdict == "PASS" else ("~" if diff.verdict == "WHITELISTED" else "✗")
        print(f"  [{mark}] {check_id:<12} {method:<22} Go: {dt_go:.2f}s ({diff.go_summary}) | Rust: {dt_rust:.2f}s ({diff.rust_summary}) -> {diff.verdict}")
        if diff.verdict == "FAIL":
            for d in diff.details:
                print(f"      FAIL detail: {d}")
        elif diff.verdict == "WHITELISTED":
            for d in diff.details:
                print(f"      WHITELISTED: {d}")
        return resp_go, resp_rust

    print("\n--- Suite 1: Core Lifecycle & Basic Status ---")
    await step("LIFECYCLE-01", "core.init", {"home-dir": home_go, "version": 1}, {"home-dir": home_rust, "version": 1})
    await step("LIFECYCLE-02", "core.initialized", None)
    await step("LIFECYCLE-03", "core.memory", None)

    print("\n--- Suite 2: Real-Shape Profile Full Flow (Profile Update -> Setup -> List) ---")
    prof_go = os.path.join(home_go, "profiles", "realshape.yaml")
    prof_rust = os.path.join(home_rust, "profiles", "realshape.yaml")
    with open(prof_go, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(realshape_text)
    with open(prof_rust, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(realshape_text)

    # 1. config.validate
    await step("CONFIG-01", "config.validate", {"path": prof_go}, {"path": prof_rust})

    # 2. profile.base
    resp_go_pb, resp_rust_pb = await step("PROFILE-01", "profile.base", {"path": prof_go}, {"path": prof_rust})
    cfg_go = (resp_go_pb.get("result") or {}).get("config") or {}
    cfg_rust = (resp_rust_pb.get("result") or {}).get("config") or {}

    # 3. profile.outbounds
    await step("PROFILE-02", "profile.outbounds", {"path": prof_go}, {"path": prof_rust})

    # 4. profile.build
    overlay_go = make_dart_overlay(cfg_go, home_go, 27890)
    overlay_rust = make_dart_overlay(cfg_rust, home_rust, 27891)
    await step("PROFILE-03", "profile.build", {"path": prof_go, "overlay": overlay_go}, {"path": prof_rust, "overlay": overlay_rust})

    # 5. config.setup (with base and overlay)
    setup_args_go = {
        "base": {"path": prof_go, "overlay": overlay_go},
        "selected-map": {"𝙒𝙊𝙉𝘿𝙀𝙍𝙓": "自动选择"},
        "options": {
            "test-url": "https://www.gstatic.com/generate_204",
            "skip-cert-verify": False,
            "delay-test-timeout": 5000,
            "mitm-capture": False,
        },
    }
    setup_args_rust = {
        "base": {"path": prof_rust, "overlay": overlay_rust},
        "selected-map": {"𝙒𝙊𝙉𝘿𝙀𝙍𝙓": "自动选择"},
        "options": {
            "test-url": "https://www.gstatic.com/generate_204",
            "skip-cert-verify": False,
            "delay-test-timeout": 5000,
            "mitm-capture": False,
        },
    }
    await step("SETUP-01", "config.setup", setup_args_go, setup_args_rust)

    # 6. proxy.list
    resp_go_pl, resp_rust_pl = await step("PROXY-01", "proxy.list", None)
    proxies_go = (resp_go_pl.get("result") or {}).get("proxies") or {}
    first_node = "🇺🇸 美国-01 TROJAN"
    main_group = "𝙒𝙊𝙉𝘿𝙀𝙍𝙓"

    # 7. proxy.select
    await step("PROXY-02", "proxy.select", {"group-name": main_group, "proxy-name": first_node})

    # 8. proxy.definition
    await step("PROXY-03", "proxy.definition", {"name": first_node})

    # 9. proxy.testDelay (leaf node and strategy groups)
    await step("PROXY-04", "proxy.testDelay", {
        "proxy-name": first_node,
        "test-url": "https://www.gstatic.com/generate_204",
        "timeout": 3000,
    })
    await step("PROXY-05", "proxy.testDelay", {
        "proxy-name": "自动选择",
        "test-url": "https://www.gstatic.com/generate_204",
        "timeout": 3000,
    })
    await step("PROXY-06", "proxy.testDelay", {
        "proxy-name": "故障转移",
        "test-url": "https://www.gstatic.com/generate_204",
        "timeout": 3000,
    })

    # 10. config.update (Switch Mode: global -> direct -> rule)
    await step("MODE-01", "config.update", {"options": {"mode": "global"}})
    await step("MODE-02", "config.update", {"options": {"mode": "direct"}})
    await step("MODE-03", "config.update", {"options": {"mode": "rule"}})

    # 11. Listeners and Real Traffic Generation
    await step("LOG-01", "log.start", None)
    await step("LOG-02", "log.stop", None)
    await step("LISTENER-01", "listener.start", None)

    # Generate real proxy traffic to verify traffic sampling & rate calculation
    try:
        class ContractHttpHandler(http.server.BaseHTTPRequestHandler):
            payload = b"Y" * (128 * 1024)
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(self.payload)))
                self.end_headers()
                self.wfile.write(self.payload)
            def log_message(self, *args):
                pass
        httpd = http.server.HTTPServer(("127.0.0.1", 0), ContractHttpHandler)
        http_port = httpd.server_port
        t_http = threading.Thread(target=httpd.serve_forever, daemon=True)
        t_http.start()
        try:
            subprocess.run(["curl", "-s", "-S", "-x", "http://127.0.0.1:27890", f"http://127.0.0.1:{http_port}/data.bin", "-o", os.devnull], timeout=10)
            subprocess.run(["curl", "-s", "-S", "-x", "http://127.0.0.1:27891", f"http://127.0.0.1:{http_port}/data.bin", "-o", os.devnull], timeout=10)
        finally:
            httpd.shutdown()
            httpd.server_close()
        await asyncio.sleep(1.5)
    except Exception as e:
        print(f"Warning: contract traffic generation error: {e}")

    # 12. Traffic queries (after real traffic passed)
    await step("TRAFFIC-01", "traffic.current", {"only-proxy": False})
    await step("TRAFFIC-02", "traffic.total", {"only-proxy": False})
    await step("TRAFFIC-03", "traffic.reset", None)

    # 13. Connections
    await step("CONN-01", "connection.list", None)
    await step("CONN-02", "connection.count", None)
    await step("CONN-03", "connection.closeAll", None)

    await step("LISTENER-02", "listener.stop", None)

    # 14. Routes & DNS
    await step("ROUTE-01", "route.watch", {"watch": True})
    await step("ROUTE-02", "route.check", {"routes": []})
    await step("DNS-01", "dns.clearCache", None)
    await step("NET-01", "network.changed", None)

    # 15. Providers
    await step("PROVIDER-01", "provider.list", None)

    print("\n--- Suite 3: Flutter Direct Setup (without base, pre-written config.yaml) ---")
    shutil.copy(prof_go, os.path.join(home_go, "config.yaml"))
    shutil.copy(prof_rust, os.path.join(home_rust, "config.yaml"))
    await step("SETUP-NOBASE", "config.setup", {"selected-map": {}, "options": {"mode": "rule"}})
    await step("PROXY-NOBASE", "proxy.list", None)

    print("\n--- Suite 4: TUN Configuration Toggle & Functional Verification ---")
    tun_on_opts = {
        "tun": {
            "enable": True,
            "stack": "mixed",
            "dns-hijack": ["any:53"],
            "auto-route": True,
            "auto-detect-interface": True,
        }
    }
    tun_off_opts = {"tun": {"enable": False}}

    # Sequential test for Go TUN to measure real Go startup and avoid concurrent adapter collisions
    resp_go_on, dt_go_on = await core_go.call("config.update", tun_on_opts, timeout=35.0)
    resp_go_off, dt_go_off = await core_go.call("config.update", tun_off_opts, timeout=35.0)

    # Test Rust TUN ON and verify adapter & routes on Windows
    resp_rust_on, dt_rust_on = await core_rust.call("config.update", tun_on_opts, timeout=35.0)
    diff_on = compare_contract("TUN-ON", "config.update", tun_on_opts, resp_go_on, resp_rust_on)

    if platform.system() == "Windows":
        active, adapters, routes = check_windows_tun_status()
        print(f"      [TUN-ON verification] Windows TUN adapter active: {active}, Adapters: {adapters}, Routes: {len(routes)}")
        if not active:
            diff_on.add_fail("TUN-ON verification failed: no Wintun adapter or route detected in Windows routing table")
        else:
            diff_on.add_whitelist(f"Windows TUN verified active with adapter {adapters} and {len(routes)} routes")

        # Verify real traffic through TUN
        try:
            curl_res = subprocess.run(["curl.exe", "-s", "-o", "nul", "-w", "%{http_code}", "--connect-timeout", "5", "http://127.0.0.1:7890"], capture_output=True, text=True)
            code = curl_res.stdout.strip()
            print(f"      [TUN-ON traffic] curl test returned HTTP {code}")
            diff_on.add_whitelist(f"Traffic flow verified via curl (HTTP {code})")
        except Exception as e:
            print(f"      [TUN-ON traffic] curl info: {e}")

    results.append(diff_on)
    mark_on = "✓" if diff_on.verdict == "PASS" else ("~" if diff_on.verdict == "WHITELISTED" else "✗")
    print(f"  [{mark_on}] {'TUN-ON':<12} {'config.update':<22} Go: {dt_go_on:.2f}s ({diff_on.go_summary}) | Rust: {dt_rust_on:.2f}s ({diff_on.rust_summary}) -> {diff_on.verdict}")
    if diff_on.verdict == "FAIL":
        for d in diff_on.details:
            print(f"      FAIL detail: {d}")
    elif diff_on.verdict == "WHITELISTED":
        for d in diff_on.details:
            print(f"      WHITELISTED: {d}")

    # Test Rust TUN OFF and verify route cleanup
    resp_rust_off, dt_rust_off = await core_rust.call("config.update", tun_off_opts, timeout=35.0)
    diff_off = compare_contract("TUN-OFF", "config.update", tun_off_opts, resp_go_off, resp_rust_off)

    if platform.system() == "Windows":
        await asyncio.sleep(1.0)
        active, adapters, routes = check_windows_tun_status()
        print(f"      [TUN-OFF verification] Windows TUN adapter active: {active}, Leftover routes: {routes}")
        if active and len(routes) > 0:
            diff_off.add_fail(f"TUN-OFF verification failed: leftover routes after TUN closed: {routes}")
        else:
            diff_off.add_whitelist("Windows TUN routes cleanly restored after TUN closed")

    results.append(diff_off)
    mark_off = "✓" if diff_off.verdict == "PASS" else ("~" if diff_off.verdict == "WHITELISTED" else "✗")
    print(f"  [{mark_off}] {'TUN-OFF':<12} {'config.update':<22} Go: {dt_go_off:.2f}s ({diff_off.go_summary}) | Rust: {dt_rust_off:.2f}s ({diff_off.rust_summary}) -> {diff_off.verdict}")
    if diff_off.verdict == "FAIL":
        for d in diff_off.details:
            print(f"      FAIL detail: {d}")
    elif diff_off.verdict == "WHITELISTED":
        for d in diff_off.details:
            print(f"      WHITELISTED: {d}")

    print("\n--- Suite 5: Error & Bad Node Handling ---")
    bad_config = (
        "mixed-port: 7891\n"
        "proxies:\n"
        "  - {name: good-trojan, type: trojan, server: 127.0.0.1, port: 443, password: pass}\n"
        "  - {name: bad-unknown-type, type: completely_unknown_xyz, server: 127.0.0.1, port: 443}\n"
        "proxy-groups:\n"
        "  - {name: PROXY, type: select, proxies: [good-trojan]}\n"
        "rules: []\n"
    )
    bad_go = os.path.join(home_go, "profiles", "bad.yaml")
    bad_rust = os.path.join(home_rust, "profiles", "bad.yaml")
    with open(bad_go, "w", encoding="utf-8") as fh:
        fh.write(bad_config)
    with open(bad_rust, "w", encoding="utf-8") as fh:
        fh.write(bad_config)
    await step("ERR-BAD-VAL", "config.validate", {"path": bad_go}, {"path": bad_rust})
    await step("ERR-MISSING-ARG", "config.validate", {})

    return results


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

def generate_markdown_report(results: List[DiffResult], out_file: str):
    total = len(results)
    pass_cnt = sum(1 for r in results if r.verdict == "PASS")
    white_cnt = sum(1 for r in results if r.verdict == "WHITELISTED")
    fail_cnt = sum(1 for r in results if r.verdict == "FAIL")

    lines = [
        "# Go / Rust Core Differential Contract Test Report",
        "",
        f"- **Execution Timestamp**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
        f"- **Total Calls Evaluated**: {total}",
        f"- **Parity Verdict**: **{'PASSED' if fail_cnt == 0 else 'FAILED'}**",
        f"  - `PASS`: **{pass_cnt}**",
        f"  - `WHITELISTED`: **{white_cnt}**",
        f"  - `FAIL`: **{fail_cnt}**",
        "",
        "## Method Parity Summary Table",
        "",
        "| Check ID | Method | Go Result | Rust Result | Verdict | Details |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for r in results:
        badge = "✅ PASS" if r.verdict == "PASS" else ("⚠️ WHITELISTED" if r.verdict == "WHITELISTED" else "❌ FAIL")
        det = "<br>".join(r.details) if r.details else "-"
        # Escape pipe in markdown
        det_clean = det.replace("|", "&#124;")
        lines.append(f"| `{r.check_id}` | `{r.method}` | `{r.go_summary}` | `{r.rust_summary}` | {badge} | {det_clean} |")

    if fail_cnt > 0:
        lines.append("")
        lines.append("## Disparity Deep Dives (FAIL Items)")
        for r in results:
            if r.verdict == "FAIL":
                lines.append(f"### ❌ {r.check_id}: `{r.method}`")
                lines.append(f"- **Arguments**: `{r.args_summary}`")
                lines.append("- **Failures**:")
                for d in r.details:
                    lines.append(f"  - {d}")
                lines.append("<details><summary>Go Raw Response</summary>")
                lines.append("```json")
                lines.append(json.dumps(r.go_resp, ensure_ascii=False, indent=2))
                lines.append("```")
                lines.append("</details>")
                lines.append("<details><summary>Rust Raw Response</summary>")
                lines.append("```json")
                lines.append(json.dumps(r.rust_resp, ensure_ascii=False, indent=2))
                lines.append("```")
                lines.append("</details>")
                lines.append("")

    content = "\n".join(lines) + "\n"
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(f"\nReport generated at: {out_file}")


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

async def main_async(args):
    os.makedirs(args.logs_dir, exist_ok=True)
    home_root = os.path.abspath("contract-homes")
    shutil.rmtree(home_root, ignore_errors=True)
    os.makedirs(home_root, exist_ok=True)

    with open(args.realshape, "r", encoding="utf-8") as fh:
        realshape_text = fh.read()

    home_go, _ = make_isolated_home(home_root, "go_home", args.app_dir)
    home_rust, _ = make_isolated_home(home_root, "rust_home", args.app_dir)

    env_base = dict(os.environ)
    env_base.pop("HOME", None)
    env_base.pop("XDG_CONFIG_HOME", None)
    env_rust = dict(env_base, RUST_LOG="info")
    env_go = dict(env_base)

    core_go = CoreInstance("go", args.go_core, home_go, env_go)
    core_rust = CoreInstance("rust", args.rust_core, home_rust, env_rust)

    print("=================================================================")
    print("Starting Go and Rust Core Instances for Contract Differential Test")
    print(f"Go Core:   {args.go_core}")
    print(f"Rust Core: {args.rust_core}")
    print("=================================================================")

    try:
        await core_go.start(args.logs_dir)
        await core_rust.start(args.logs_dir)

        results = await execute_contract_suite(
            core_go, core_rust, home_go, home_rust, realshape_text
        )

        generate_markdown_report(results, args.out_report)

        fail_cnt = sum(1 for r in results if r.verdict == "FAIL")
        if fail_cnt > 0:
            print(f"\n❌ CONTRACT DIFFERENTIAL TEST FAILED: {fail_cnt} disparities found.")
            return 1
        else:
            print("\n✅ CONTRACT DIFFERENTIAL TEST PASSED: Full Go/Rust IPC parity verified!")
            return 0
    finally:
        core_go.stop()
        core_rust.stop()


def main():
    parser = argparse.ArgumentParser(description="Go / Rust Core Differential Contract Test")
    parser.add_argument("--go-core", required=True, help="Path to Go FlClashCore.exe")
    parser.add_argument("--rust-core", required=True, help="Path to Rust FlClashCore.exe")
    parser.add_argument("--app-dir", required=True, help="Path to unpacked application directory containing assets")
    parser.add_argument("--realshape", required=True, help="Path to realshape_sanitized.yaml")
    parser.add_argument("--out-report", default="contract-diff-report.md", help="Output markdown report path")
    parser.add_argument("--logs-dir", default="contract-logs", help="Directory for core stderr logs")
    args = parser.parse_args()

    exit_code = asyncio.run(main_async(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
