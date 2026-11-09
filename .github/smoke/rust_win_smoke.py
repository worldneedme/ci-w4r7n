#!/usr/bin/env python3
"""WONDERX pure-Rust FlClashCore Windows smoke.

Acts as the Flutter host: owns a named pipe server, launches FlClashCore.exe
<pipe>, speaks the length-prefixed (u32 LE) JSON MethodCall protocol, and runs
the same call sequence the UI uses on "start":
  core.init -> profile.base -> config.setup(base{path,overlay}) -> proxy.list
  -> listener.start
All servers are dummies (127.0.0.1); no real credentials.

Usage: python rust_win_smoke.py --core FlClashCore.exe --app-dir <extracted zip>
       [--loops 5] [--out smoke-out]
Exit 0 only if every gated (user-like) iteration passed.
"""
import argparse
import asyncio
import http.server
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

UUID = "11111111-2222-3333-4444-555555555555"
PBK = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"  # dummy x25519 pubkey shape

PROXIES = [
    '{ name: "🇭🇰 香港 SS", type: ss, server: 127.0.0.1, port: 20001, cipher: aes-128-gcm, password: dummy, udp: true }',
    '{ name: "🇯🇵 日本 VMess WS", type: vmess, server: 127.0.0.1, port: 20002, uuid: ' + UUID + ', alterId: 0, cipher: auto, udp: true, tls: true, skip-cert-verify: false, servername: a.example.com, network: ws, ws-opts: { path: /ws, headers: { Host: a.example.com } } }',
    '{ name: "🇺🇸 美国 VLESS WS TLS", type: vless, server: 127.0.0.1, port: 20003, uuid: ' + UUID + ', udp: true, tfo: true, tls: true, skip-cert-verify: false, client-fingerprint: chrome, servername: b.example.com, network: ws, ws-opts: { path: /vl, headers: { Host: b.example.com } } }',
    '{ name: "🇸🇬 新加坡 Reality", type: vless, server: 127.0.0.1, port: 20004, uuid: ' + UUID + ', udp: true, tfo: true, flow: xtls-rprx-vision, tls: true, skip-cert-verify: false, client-fingerprint: chrome, servername: www.microsoft.com, reality-opts: { public-key: ' + PBK + ', short-id: "" } }',
    '{ name: "🇸🇬 新加坡 XHTTP", type: vless, server: 127.0.0.1, port: 20005, uuid: ' + UUID + ', udp: true, tfo: true, tls: true, skip-cert-verify: false, client-fingerprint: chrome, servername: www.apple.com, reality-opts: { public-key: ' + PBK + ', short-id: "" }, network: xhttp, xhttp-opts: { path: /xh, host: www.apple.com, mode: auto } }',
    '{ name: "🇹🇼 台湾 Trojan", type: trojan, server: 127.0.0.1, port: 20006, password: dummy, udp: true, sni: c.example.com, skip-cert-verify: false }',
    '{ name: "🇰🇷 韩国 TUIC", type: tuic, server: 127.0.0.1, port: 20007, uuid: ' + UUID + ', password: dummy, alpn: [h3], disable-sni: false, reduce-rtt: false, udp-relay-mode: native, congestion-controller: bbr, skip-cert-verify: false, sni: d.example.com }',
    '{ name: "🇩🇪 德国 AnyTLS", type: anytls, server: 127.0.0.1, port: 20008, password: dummy, skip-cert-verify: false, udp: true, sni: e.example.com, client-fingerprint: chrome }',
    '{ name: "🇬🇧 英国 Juicity", type: juicity, server: 127.0.0.1, port: 20009, uuid: ' + UUID + ', password: dummy, sni: f.example.com, skip-cert-verify: false, alpn: [h3], congestion-controller: bbr, udp: true }',
    '{ name: "🇫🇷 法国 Naive", type: naive, server: 127.0.0.1, port: 20010, username: ' + UUID + ', password: dummy, client-fingerprint: chrome, udp: false, alpn: [h2], sni: g.example.com, skip-cert-verify: false }',
    '{ name: "🇳🇱 荷兰 Hy2", type: hysteria2, server: 127.0.0.1, password: dummy, skip-cert-verify: false, sni: h.example.com, udp: true, port: 20011, ports: 20011-20020, mport: 20011-20020 }',
    '{ name: "🇨🇦 加拿大 Mieru", type: mieru, server: 127.0.0.1, transport: TCP, udp: true, username: ' + UUID + ', password: dummy, multiplexing: MULTIPLEXING_LOW, port: 20012 }',
    '{ name: "🇦🇺 澳洲 Hysteria1", type: hysteria, server: 127.0.0.1, port: 20013, udp: true, skip-cert-verify: false, sni: i.example.com, auth_str: dummy, up: 100, down: 100, protocol: udp }',
    "{ name: \"🇮🇳 印度 VLESS 字符串端口\", type: vless, server: 127.0.0.1, port: '20014', uuid: " + UUID + ", udp: true, tls: true, servername: j.example.com, network: ws, ws-opts: { path: /s } }",
]


def node_name(flow):
    return flow.split('name: "', 1)[1].split('"', 1)[0]


NODE_NAMES = [node_name(p) for p in PROXIES]

RULES_COMMON = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,1.1.1.1/32,WONDERX,no-resolve",
    "DOMAIN-SUFFIX,services.googleapis.cn,WONDERX",
    "DOMAIN,safebrowsing.urlsec.qq.com,DIRECT",
    "DOMAIN-SUFFIX,apple.com,DIRECT",
    "DOMAIN-KEYWORD,-cn,DIRECT",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "IP-CIDR6,fe80::/10,DIRECT",
]


def build_subscription(proxies=PROXIES, geoip=True):
    names = [node_name(p) for p in proxies]
    q = lambda xs: "[" + ", ".join('"%s"' % x for x in xs) + "]"
    rules = list(RULES_COMMON)
    if geoip:
        rules.append("GEOIP,CN,DIRECT")
    rules.append("MATCH,WONDERX")
    lines = [
        "mixed-port: 7890", "allow-lan: true", "bind-address: '*'", "mode: rule",
        "log-level: info", "external-controller: '127.0.0.1:9090'",
        "dns:", "    enable: true", "    ipv6: false",
        "    default-nameserver: [223.5.5.5, 119.29.29.29]",
        "    enhanced-mode: fake-ip", "    fake-ip-range: 198.18.0.1/16",
        "    use-hosts: true", "    respect-rules: true",
        "    proxy-server-nameserver: [223.5.5.5, 119.29.29.29]",
        "    nameserver: ['https://1.1.1.1/dns-query', 'https://dns.google/dns-query']",
        "    fallback: ['https://1.1.1.1/dns-query', 'https://dns.google/dns-query']",
        "    fallback-filter: { geoip: true, geoip-code: CN, geosite: [gfw], ipcidr: [240.0.0.0/4], domain: ['+.google.com'] }",
        "proxies:",
    ]
    lines += ["    - " + p for p in proxies]
    lines += [
        "proxy-groups:",
        "    - { name: WONDERX, type: select, proxies: " + q(["自动选择", "故障转移"] + names) + " }",
        "    - { name: 自动选择, type: url-test, proxies: " + q(names) + ", url: 'http://www.gstatic.com/generate_204', interval: 300, tolerance: 50, lazy: false }",
        "    - { name: 故障转移, type: fallback, proxies: " + q(names) + ", url: 'http://www.gstatic.com/generate_204', interval: 300, lazy: false }",
        "rules:",
    ]
    lines += ["    - " + r for r in rules]
    return "\n".join(lines) + "\n"


def dart_like_overlay(base_config, home):
    """Mirror lib/common/task.dart _makeRealProfileTask on profile.base config."""
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
        "disable-keep-alive": False, "routing-mark": 0, "mixed-port": 7890,
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
    # Flutter encodes with a YAML encoder; JSON is valid YAML 1.2 flow.
    return json.dumps(raw, ensure_ascii=False, indent=1)


class Host(asyncio.Protocol):
    def __init__(self):
        self.buf = b""
        self.waiters = {}
        self.events = 0
        self.received_messages = []
        self.connected = asyncio.get_event_loop().create_future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        if not self.connected.done():
            self.connected.set_result(True)

    def data_received(self, data):
        self.buf += data
        while len(self.buf) >= 4:
            n = struct.unpack("<I", self.buf[:4])[0]
            if len(self.buf) < 4 + n:
                break
            payload, self.buf = self.buf[4:4 + n], self.buf[4 + n:]
            try:
                msg = json.loads(payload)
            except Exception as e:  # noqa
                print("  !! undecodable frame:", e, payload[:200])
                continue
            if msg.get("method") == "message":
                self.events += 1
                self.received_messages.append(msg)
                continue
            fut = self.waiters.pop(msg.get("id"), None)
            if fut and not fut.done():
                fut.set_result(msg)

    def connection_lost(self, exc):
        for f in self.waiters.values():
            if not f.done():
                f.set_exception(ConnectionError("pipe closed: %s" % exc))

    async def call(self, method, args=None, timeout=60):
        cid = uuid.uuid4().hex
        fut = asyncio.get_event_loop().create_future()
        self.waiters[cid] = fut
        body = json.dumps({"id": cid, "method": method, "arguments": args},
                          ensure_ascii=False).encode()
        self.transport.write(struct.pack("<I", len(body)) + body)
        t0 = time.monotonic()
        try:
            resp = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self.waiters.pop(cid, None)
            return {"_timeout": True}, time.monotonic() - t0
        if resp.get("file"):
            try:
                with open(resp["file"], encoding="utf-8") as fh:
                    resp["result"] = json.load(fh)
            except Exception as e:  # noqa
                resp["result"] = {"_spill_error": str(e)}
        return resp, time.monotonic() - t0


def short(resp, n=400):
    s = json.dumps(resp, ensure_ascii=False)
    return s if len(s) <= n else s[:n] + "..."


def summarize_proxies(resp):
    res = resp.get("result") or {}
    proxies = res.get("proxies") or {}
    leaves = [n for n in NODE_NAMES if n in proxies]
    missing = [n for n in NODE_NAMES if n not in proxies]
    groups = res.get("all") or []
    wx = proxies.get("WONDERX") or {}
    return leaves, missing, groups, wx


def start_1mb_server():
    class OneMbHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            chunk = b"X" * 65536
            total_chunks = 16  # 1048576 bytes
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(chunk) * total_chunks))
            self.end_headers()
            for _ in range(total_chunks):
                self.wfile.write(chunk)
                time.sleep(0.02)
        def log_message(self, *args):
            pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), OneMbHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv.server_port, srv


async def session(core, home, cwd, env, label, variants, setup_timeout):
    """One core process; runs each variant's config.setup + proxy.list."""
    loop = asyncio.get_event_loop()
    pipe = r"\\.\pipe\wxsmoke_%s" % uuid.uuid4().hex[:12]
    host = Host()
    servers = await loop.start_serving_pipe(lambda: host, pipe)
    log_path = os.path.join(home, "core-stderr.log")
    logf = open(log_path, "wb")
    proc = subprocess.Popen([core, pipe], cwd=cwd, env=env, stdout=logf, stderr=logf)
    results = {}
    try:
        try:
            await asyncio.wait_for(host.connected, 15)
        except asyncio.TimeoutError:
            print("  [%s] FAIL core never connected to pipe (exit=%s)" % (label, proc.poll()))
            return {"connect": False}
        r, dt = await host.call("core.init", {"home-dir": home, "version": 1}, 20)
        print("  [%s] core.init %.2fs -> %s" % (label, dt, short(r)))
        for vname, prepare in variants:
            args = prepare(host)
            if asyncio.iscoroutine(args):
                args = await args
            r, dt = await host.call("config.setup", args, setup_timeout)
            err = r.get("error") if isinstance(r, dict) else None
            print("  [%s/%s] config.setup %.2fs -> %s" % (label, vname, dt, short(r, 900)))
            pl, _ = await host.call("proxy.list", None, 20)
            leaves, missing, groups, wx = summarize_proxies(pl)
            print("  [%s/%s] proxy.list: %d/%d nodes, groups=%s, WONDERX.all=%d now=%r"
                  % (label, vname, len(leaves), len(NODE_NAMES), groups,
                     len(wx.get("all") or []), wx.get("now")))
            if missing:
                print("  [%s/%s] missing nodes: %s" % (label, vname, missing))
            results[vname] = {"timeout": bool(r.get("_timeout")), "error": err,
                              "secs": round(dt, 2), "nodes": len(leaves),
                              "missing": missing, "groups": groups}
        r, dt = await host.call("listener.start", None, 20)
        print("  [%s] listener.start %.2fs -> %s" % (label, dt, short(r)))
        results["listener"] = r.get("error")
        results["events"] = host.events

        # Functional assertions (A, B, C, E, F)
        try:
            # B: Start log stream
            await host.call("log.start", None, 10)

            # Start 1MB download and monitor traffic rates
            srv_port, srv = start_1mb_server()
            max_current_down = 0
            max_conn_count = 0
            download_done = False

            async def sample_rates():
                nonlocal max_current_down, max_conn_count
                for _ in range(50):
                    rc, _ = await host.call("traffic.current", None, 5)
                    d = (rc.get("result") or {}).get("down", 0)
                    if d > max_current_down:
                        max_current_down = d
                    r_cnt, _ = await host.call("connection.count", None, 5)
                    c = r_cnt.get("result") or 0
                    if c > max_conn_count:
                        max_conn_count = c
                    if download_done and max_current_down > 0 and max_conn_count > 0:
                        break
                    await asyncio.sleep(0.05)

            rate_task = asyncio.create_task(sample_rates())
            try:
                cmd = ["curl", "-s", "-S", "-x", "http://127.0.0.1:7890",
                       f"http://127.0.0.1:{srv_port}/1mb.bin",
                       "-o", "nul" if os.name == "nt" else "/dev/null"]
                cp = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, timeout=15)
                if cp.returncode != 0:
                    print(f"  [{label}] curl 1MB download: code={cp.returncode} err={cp.stderr[:200]}")
            finally:
                download_done = True
                await rate_task
                srv.shutdown()
                srv.server_close()

            await asyncio.sleep(1.5)

            # A: traffic.total.down >= 1MB and traffic.current.down > 0 during run
            r_tot, _ = await host.call("traffic.total", None, 10)
            down = (r_tot.get("result") or {}).get("down", 0)
            print(f"  [{label}] traffic.total: down={down}, max_current_down={max_current_down}")
            if down < 1048576:
                results["traffic_error"] = f"traffic.total.down expected >= 1048576, got {down}"
            if max_current_down <= 0:
                results["traffic_error"] = f"traffic.current.down expected > 0 at least once during 1MB transfer, got {max_current_down}"

            # F: connection.list has connections and connection.count > 0
            r_conn, _ = await host.call("connection.list", None, 10)
            cdown = (r_conn.get("result") or {}).get("downloadTotal", 0)
            if cdown < 1048576:
                results["traffic_error"] = f"connection.list.downloadTotal expected >= 1048576, got {cdown}"
            r_count, _ = await host.call("connection.count", None, 10)
            cnt = r_count.get("result", 0)
            print(f"  [{label}] connection.count: now={cnt}, max_during_transfer={max_conn_count}")
            if max_conn_count <= 0 and cnt <= 0:
                results["conn_error"] = f"connection.count expected > 0 during or after 1MB transfer, got max={max_conn_count}, now={cnt}"

            # B: log event received within 5s of log.start
            await asyncio.sleep(1.0)
            has_log_event = host.events > 0 or any(
                isinstance(m.get("arguments"), list) and any(a.get("type") == "log" for a in m.get("arguments", []))
                for m in host.received_messages
            )
            print(f"  [{label}] log events received: {host.events} (total messages: {len(host.received_messages)})")
            if not has_log_event:
                results["log_error"] = "log.start: expected at least 1 log event within 5s"

            # C: probe.outboundIp returns non-empty and non-0.0.0.0
            r_ip, _ = await host.call("probe.outboundIp", {"proxy-name": "DIRECT", "timeout": 5000}, 10)
            ip_res = r_ip.get("result") or {}
            ip_val = ip_res.get("body") or ip_res.get("ip") or ""
            print(f"  [{label}] probe.outboundIp: {ip_val}")
            if not ip_val or ip_val == "0.0.0.0":
                results["probe_ip_error"] = f"probe.outboundIp expected non-empty non-0.0.0.0, got: {ip_res}"

            # E: route.watch and route.check have core-epoch and route-version matching Go
            r_rw, _ = await host.call("route.watch", {"watch": False}, 10)
            rw_res = r_rw.get("result") or {}
            if "core-epoch" not in rw_res or "route-version" not in rw_res:
                results["route_watch_error"] = f"route.watch missing core-epoch/route-version: {rw_res}"
            r_rc, _ = await host.call("route.check", {"routes": []}, 10)
            rc_res = r_rc.get("result") or {}
            if "core-epoch" not in rc_res or "route-version" not in rc_res or "held" not in rc_res:
                results["route_check_error"] = f"route.check missing core-epoch/route-version/held: {rc_res}"

            # G: core.memory returns positive RSS (read_rss_bytes invocation verification)
            r_mem, _ = await host.call("core.memory", None, 10)
            mem_res = r_mem.get("result") or {}
            rss = mem_res.get("rss", 0)
            print(f"  [{label}] core.memory: rss={rss} bytes ({rss / (1024*1024):.2f} MB)")
            if rss <= 0:
                results["memory_error"] = f"core.memory expected positive rss, got {mem_res}"

        except Exception as e:
            print(f"  [{label}] functional verification error: {e}")
            results["functional_error"] = str(e)

        return results
    finally:
        try:
            host.transport and host.transport.close()
        except Exception:
            pass
        for s in servers:
            s.close()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        with open(log_path, "rb") as fh:
            tail = fh.read()[-6000:].decode("utf-8", "replace")
        print("  [%s] core exit=%s stderr tail:\n%s" % (label, proc.poll(),
              "\n".join("      | " + l for l in tail.splitlines()[-60:])))


def make_home(root, name, app_dir, sub_yaml):
    home = os.path.join(root, name)
    shutil.rmtree(home, ignore_errors=True)
    os.makedirs(os.path.join(home, "profiles"), exist_ok=True)
    # Flutter initGeo copies these four assets into the home dir.
    assets = os.path.join(app_dir, "data", "flutter_assets", "assets", "data")
    copied = []
    if os.path.isdir(assets):
        for f in os.listdir(assets):
            shutil.copy(os.path.join(assets, f), os.path.join(home, f))
            copied.append(f)
    prof = os.path.join(home, "profiles", "1.yaml")
    with open(prof, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sub_yaml)
    return home, prof, copied


def flutter_variants(prof, home, include_nobase=True):
    async def with_base(host):
        pb, dt = await host.call("profile.base", {"path": prof}, 20)
        cfg = (pb.get("result") or {}).get("config")
        print("    profile.base %.2fs config-type=%s keys=%s err=%s" % (
            dt, type(cfg).__name__, sorted(cfg.keys())[:12] if isinstance(cfg, dict) else None,
            pb.get("error")))
        return {"base": {"path": prof, "overlay": dart_like_overlay(cfg, home)},
                "selected-map": {"WONDERX": NODE_NAMES[0]},
                "options": {"test-url": "https://www.gstatic.com/generate_204",
                            "skip-cert-verify": False, "delay-test-timeout": 5000,
                            "mitm-capture": False}}
    v = [("base+overlay", with_base),
         ("base-no-overlay", lambda h: {"base": {"path": prof, "overlay": ""},
                                        "selected-map": {}, "options": {}})]
    if include_nobase:
        def nobase(h):
            shutil.copy(prof, os.path.join(home, "config.yaml"))
            return {"selected-map": {}, "options": {}}
        v.append(("no-base(config.yaml)", nobase))
    return v


def user_like_env():
    env = dict(os.environ)
    for k in ("HOME", "XDG_CONFIG_HOME"):
        env.pop(k, None)
    env["RUST_LOG"] = "info"
    return env


def blackhole_github():
    hosts = r"C:\Windows\System32\drivers\etc\hosts"
    names = ["github.com", "api.github.com", "objects.githubusercontent.com",
             "raw.githubusercontent.com", "release-assets.githubusercontent.com",
             "github-releases.githubusercontent.com", "codeload.github.com",
             "cdn.jsdelivr.net", "fastly.jsdelivr.net", "testingcf.jsdelivr.net"]
    try:
        shutil.copy(hosts, hosts + ".wxsmoke.bak")
        with open(hosts, "a", encoding="ascii") as fh:
            fh.write("\n" + "".join("0.0.0.0 %s\n" % n for n in names))
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True)
        print("hosts: github/jsdelivr blackholed (emulates CN network)")
    except Exception as e:  # noqa
        print("hosts: could not blackhole:", e)


# ---------------------------------------------------------------------------
# Real-shape replica: realshape_sanitized.yaml mirrors the production
# subscription's structure (30 nodes: vless ws/reality/xhttp+download-settings,
# trojan, juicity hop, hysteria2 ports, mieru, ss-2022, anytls; 3 groups with
# the branded unicode name; 530 rules; fallback-filter DNS) with every server,
# credential, SNI, path and rule payload replaced by dummies.
# It is driven through the exact Flutter profile-update path:
#   config.validate(temp file) -> profile.base -> config.setup(base+overlay)
#   -> proxy.list (checked the way lib/common/task.dart buildGroups reads it)
#   -> listener.start -> background health checks -> proxy.testDelay x all
#   -> core still alive and answering.
# ---------------------------------------------------------------------------
FLUTTER_GROUP_TYPES = ["Selector", "URLTest", "Fallback", "LoadBalance", "Relay"]


def flutter_groups(resp):
    """Mirror buildGroups() + rule-mode currentGroupsState: iterate
    result.all, keep entries whose type is in GroupTypeExtension.valueList and
    whose hidden is exactly false. Returns (groups shown, problems)."""
    res = resp.get("result") or {}
    proxies = res.get("proxies") or {}
    out, problems = [], []
    if not isinstance(res.get("all"), list):
        problems.append("result.all missing")
        return out, problems
    for name in res["all"]:
        raw = proxies.get(name)
        if not isinstance(raw, dict):
            problems.append("all[] names a missing entry")
            continue
        if raw.get("type") not in FLUTTER_GROUP_TYPES:
            problems.append("group %r has type %r the UI drops" % (name, raw.get("type")))
            continue
        members = [proxies.get(m) for m in (raw.get("all") or [])]
        # lib/providers/state/proxies.dart currentGroupsState: in rule mode
        # only `hidden == false` groups are shown (a missing key hides it).
        if raw.get("hidden") is not False:
            if name != "GLOBAL":
                problems.append("group %r hidden in rule mode (hidden=%r)" % (name, raw.get("hidden")))
            continue
        out.append((name, raw.get("type"), len([m for m in members if m])))
    return out, problems


def realshape_expect(yaml_text):
    names, groups = [], []
    sect = None
    for line in yaml_text.splitlines():
        if not line.startswith(" ") and line.endswith(":"):
            sect = line[:-1]
        elif sect == "proxies" and line.startswith("- name: "):
            names.append(json.loads(line[8:]) if line[8:].startswith('"') else line[8:])
        elif sect == "proxy-groups" and line.startswith("- name: "):
            groups.append(json.loads(line[8:]) if line[8:].startswith('"') else line[8:])
    return names, groups


async def realshape_session(core, root, label, app_dir, env, sub_text, tun, call_timeout):
    names, want_groups = realshape_expect(sub_text)
    home, prof, _ = make_home(root, label, app_dir, sub_text)
    tmp = os.path.join(home, "tmp-download.yaml")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(sub_text)
    loop = asyncio.get_event_loop()
    host = Host()
    if os.name == "nt":
        pipe = r"\\.\pipe\wxreal_%s" % uuid.uuid4().hex[:12]
        servers = await loop.start_serving_pipe(lambda: host, pipe)
    else:  # local reproduction on Linux
        pipe = "/tmp/wxreal_%s.sock" % uuid.uuid4().hex[:12]
        servers = [await loop.create_unix_server(lambda: host, pipe)]
    logf = open(os.path.join(home, "core-stderr.log"), "wb")
    proc = subprocess.Popen([core, pipe], cwd=app_dir, env=env, stdout=logf, stderr=logf)
    fails = []

    def check(step, r, dt):
        if r.get("_timeout"):
            fails.append("%s: NO REPLY within %ss" % (step, call_timeout))
        elif r.get("_lost"):
            fails.append("%s: core gone" % step)
        print("  [%s] %s %.2fs -> %s" % (label, step, dt, short(r, 300)))

    try:
        try:
            await asyncio.wait_for(host.connected, 15)
        except asyncio.TimeoutError:
            return ["core never connected (exit=%s)" % proc.poll()]
        r, dt = await host.call("core.init", {"home-dir": home, "version": 1}, call_timeout); check("core.init", r, dt)
        r, dt = await host.call("config.validate", {"path": tmp}, call_timeout); check("config.validate", r, dt)
        if r.get("result") or r.get("error"):
            fails.append("config.validate reported an issue: %s" % short(r.get("result") or r.get("error"), 200))
        pb, dt = await host.call("profile.base", {"path": prof}, call_timeout); check("profile.base", pb, dt)
        cfg = (pb.get("result") or {}).get("config")
        ov = json.loads(dart_like_overlay(cfg, home))
        if tun:
            ov["tun"].update({"enable": True, "auto-route": True, "route-address": []})
        args = {"base": {"path": prof, "overlay": json.dumps(ov, ensure_ascii=False)},
                "selected-map": {}, "options": {"test-url": "https://www.gstatic.com/generate_204",
                "skip-cert-verify": False, "delay-test-timeout": 5000, "mitm-capture": False}}
        r, dt = await host.call("config.setup", args, call_timeout); check("config.setup", r, dt)
        if r.get("error"):
            fails.append("config.setup error: %s" % short(r["error"], 300))
        pl, dt = await host.call("proxy.list", None, call_timeout)
        print("  [%s] proxy.list %.2fs" % (label, dt))
        if pl.get("_timeout"):
            fails.append("proxy.list: NO REPLY")
        groups, problems = flutter_groups(pl)
        proxies = (pl.get("result") or {}).get("proxies") or {}
        leaves = [n for n in names if n in proxies]
        print("  [%s] UI (rule mode) groups=%s nodes=%d/%d problems=%s" % (label, groups, len(leaves), len(names), problems))
        fails += problems
        got = [g[0] for g in groups]
        for g in want_groups:
            if g not in got:
                fails.append("UI would not show group %r" % g)
        if len(leaves) < len(names):
            fails.append("nodes missing: %d/%d" % (len(leaves), len(names)))
        r, dt = await host.call("listener.start", None, call_timeout); check("listener.start", r, dt)
        await asyncio.sleep(15)
        if proc.poll() is not None:
            fails.append("core exited (code %s) during health checks" % proc.returncode)
        else:
            res = await asyncio.gather(*[host.call("proxy.testDelay", {"proxy-name": n, "test-url": "https://www.gstatic.com/generate_204", "timeout": 5000}, 40) for n in names])
            noreply = sum(1 for r, _ in res if r.get("_timeout"))
            print("  [%s] testDelay x%d: no-reply=%d" % (label, len(res), noreply))
            if noreply:
                fails.append("proxy.testDelay: %d calls got no reply" % noreply)
            if proc.poll() is not None:
                fails.append("core exited (code %s) during delay tests" % proc.returncode)
            # Group delay tests: verify group testDelay forwards to now node and returns valid value
            for g in ("自动选择", "故障转移"):
                r_g, dt_g = await host.call("proxy.testDelay", {
                    "proxy-name": g,
                    "test-url": "https://www.gstatic.com/generate_204",
                    "timeout": 5000,
                }, 40)
                check(f"proxy.testDelay({g})", r_g, dt_g)
                if r_g.get("_timeout"):
                    fails.append(f"proxy.testDelay({g}): NO REPLY")
                elif "value" not in (r_g.get("result") or {}):
                    fails.append(f"proxy.testDelay({g}): missing 'value' in response: {r_g}")
                else:
                    gval = r_g["result"]["value"]
                    print(f"  [{label}] proxy.testDelay({g}) -> {gval}")
                    if not isinstance(gval, int) or gval == 0:
                        fails.append(f"proxy.testDelay({g}) invalid value: {gval}")
            r, dt = await host.call("proxy.list", None, call_timeout)
            if r.get("_timeout"):
                fails.append("proxy.list after delay tests: NO REPLY")
            r, dt = await host.call("config.validate", {"path": tmp}, call_timeout); check("config.validate(again)", r, dt)
        return fails
    except ConnectionError as e:
        fails.append("pipe closed: %s (core exit=%s)" % (e, proc.poll()))
        return fails
    finally:
        try:
            host.transport and host.transport.close()
        except Exception:
            pass
        for s in servers:
            s.close()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
        logf.close()
        with open(os.path.join(home, "core-stderr.log"), "rb") as fh:
            data = fh.read().decode("utf-8", "replace")
        bad = [l for l in data.splitlines() if "panicked" in l or "ERROR" in l]
        print("  [%s] core exit=%s; panic/ERROR lines: %d" % (label, proc.poll(), len(bad)))
        for l in bad[:15]:
            print("      | " + l[:300])


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True)
    ap.add_argument("--app-dir", required=True)
    ap.add_argument("--loops", type=int, default=5)
    ap.add_argument("--out", default="smoke-out")
    ap.add_argument("--setup-timeout", type=int, default=90)
    ap.add_argument("--diagnostics", action="store_true")
    ap.add_argument("--realshape", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "realshape_sanitized.yaml"))
    a = ap.parse_args()
    core = os.path.abspath(a.core)
    app_dir = os.path.abspath(a.app_dir)
    root = os.path.abspath(a.out)
    os.makedirs(root, exist_ok=True)
    sub = build_subscription()
    with open(os.path.join(root, "subscription.yaml"), "w", encoding="utf-8") as fh:
        fh.write(sub)
    print("core:", core, "HOME env on runner:", os.environ.get("HOME"),
          "USERPROFILE:", os.environ.get("USERPROFILE"))

    if a.diagnostics:
        print("\n===== DIAG A: runner default env (HOME as runner sets it), network open =====")
        home, prof, copied = make_home(root, "diagA", app_dir, sub)
        print("  geo assets copied into home:", copied)
        await session(core, home, home, dict(os.environ, RUST_LOG="info"), "diagA",
                      flutter_variants(prof, home), a.setup_timeout)

    real_text = None
    if a.realshape and os.path.exists(a.realshape):
        with open(a.realshape, encoding="utf-8") as fh:
            real_text = fh.read()
    if a.diagnostics and real_text:
        print("\n===== DIAG R: real-shape replica, Flutter profile-update path, TUN on =====")
        f = await realshape_session(core, root, "realTun", app_dir, user_like_env(), real_text, True, a.setup_timeout)
        print("  DIAG R (tun):", "PASS" if not f else "FAIL " + "; ".join(f))

    blackhole_github()

    if a.diagnostics:
        print("\n===== DIAG B: per-protocol isolation (one node, no GEOIP rule) =====")
        for i, p in enumerate(PROXIES):
            home, prof, _ = make_home(root, "iso%02d" % i, app_dir,
                                      build_subscription([p], geoip=False))
            r = await session(core, home, home, user_like_env(), "iso:" + NODE_NAMES[i],
                              [("base-no-overlay", lambda h, prof=prof: {"base": {"path": prof, "overlay": ""}, "selected-map": {}, "options": {}})],
                              a.setup_timeout)
        print("\n===== DIAG C: full sub WITHOUT GEOIP rule, user-like env, CN network =====")
        home, prof, _ = make_home(root, "diagC", app_dir, build_subscription(geoip=False))
        await session(core, home, app_dir, user_like_env(), "diagC",
                      flutter_variants(prof, home, False), a.setup_timeout)

    print("\n===== GATE: %d consecutive user-like runs (no HOME, cwd=app dir, CN network) =====" % a.loops)
    verdicts = []
    for i in range(1, a.loops + 1):
        home, prof, _ = make_home(root, "run%d" % i, app_dir, sub)
        print("\n--- run %d ---" % i)
        r = await session(core, home, app_dir, user_like_env(), "run%d" % i,
                          flutter_variants(prof, home, False), a.setup_timeout)
        v = r.get("base+overlay") or {}
        ok = (r.get("connect", True) and not v.get("timeout") and not v.get("error")
              and v.get("nodes", 0) >= 1 and "WONDERX" in (v.get("groups") or [])
              and not r.get("traffic_error")
              and not r.get("conn_error")
              and not r.get("log_error")
              and not r.get("probe_ip_error")
              and not r.get("route_watch_error")
              and not r.get("route_check_error")
              and not r.get("functional_error"))
        real_fail = []
        if real_text:
            real_fail = await realshape_session(core, root, "real%d" % i, app_dir, user_like_env(), real_text, False, a.setup_timeout)
            print("RUN %d real-shape: %s" % (i, "PASS" if not real_fail else "FAIL " + "; ".join(real_fail)))
            ok = ok and not real_fail
        verdicts.append(ok)
        err_details = [f"{k}={val}" for k, val in r.items() if k.endswith("_error")]
        print("RUN %d: %s  (setup %.2fs, nodes=%s, error=%s, err_details=%s)" % (
            i, "PASS" if ok else "FAIL", v.get("secs", -1), v.get("nodes"),
            (v.get("error") or {}).get("message") if v.get("error") else ("TIMEOUT" if v.get("timeout") else None),
            err_details if err_details else "none"))
    print("\nSUMMARY:", " ".join("run%d=%s" % (i + 1, "PASS" if ok else "FAIL")
                                for i, ok in enumerate(verdicts)))
    print("GATE:", "PASS" if all(verdicts) and len(verdicts) >= 5 else "FAIL")
    return 0 if all(verdicts) and len(verdicts) >= 5 else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    sys.exit(asyncio.run(main()))
