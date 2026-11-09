#!/usr/bin/env python3
"""Windows gate: real TUN through the installed Rust Helper service.

Runs the same path the Rust app takes when the user turns TUN on:
  Helper /ping -> Helper /start (Helper launches the installed FlClashCore.exe
  as SYSTEM) -> core.init -> profile.base -> config.setup(TUN on, auto-route)
  -> listener.start.
Then checks, from outside the core:
  * the Wintun adapter exists and is Up, with routes on it;
  * plain socket traffic with no proxy configured reaches the internet
    (an IP literal and a domain, so DNS hijack is exercised too);
  * the core saw those connections (they really went through TUN);
  * Helper /stop removes the adapter and its routes and the network still works.
Exit 0 only when every check passes.
"""
import argparse
import asyncio
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rust_win_smoke import Host, dart_like_overlay, make_home, short, user_like_env  # noqa: E402

DEVICE = "WONDERX"
PIPE_PREFIX = r"\\.\pipe\FlClashCoreRust_"
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def ps(cmd, timeout=30):
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()


def adapter_up():
    rc, out, _ = ps("$a = Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
                    "Where-Object { $_.Name -eq '%s' -or $_.InterfaceAlias -eq '%s' }; "
                    "if ($a) { $a | Select-Object -First 1 -ExpandProperty Status }" % (DEVICE, DEVICE))
    return out


def route_count():
    rc, out, _ = ps("(Get-NetRoute -InterfaceAlias '%s' -ErrorAction SilentlyContinue | "
                    "Measure-Object).Count" % DEVICE)
    try:
        return int(out or "0")
    except ValueError:
        return 0


def helper(port, method, path, body=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with NO_PROXY.open(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def fetch(url, timeout=20):
    t0 = time.monotonic()
    try:
        with NO_PROXY.open(urllib.request.Request(url, headers={"User-Agent": "wx-tun-gate"}),
                           timeout=timeout) as r:
            r.read(4096)
            return r.status, time.monotonic() - t0, None
    except urllib.error.HTTPError as e:
        return e.code, time.monotonic() - t0, None
    except Exception as e:  # noqa
        return None, time.monotonic() - t0, repr(e)


async def run(a):
    fails = []
    app_dir = os.path.abspath(a.app_dir)
    with open(os.path.join(app_dir, "manifest.json"), encoding="utf-8") as fh:
        want_sha = json.load(fh)["coreSha256"]
    with open(os.path.join(app_dir, "FlClashCore.exe"), "rb") as fh:
        real_sha = hashlib.sha256(fh.read()).hexdigest()
    print("manifest coreSha256=%s file=%s" % (want_sha, real_sha))
    if want_sha != real_sha:
        return ["manifest coreSha256 does not match installed FlClashCore.exe"]

    st, body = helper(a.port, "GET", "/ping?coreSha256=" + want_sha)
    print("ping:", st, body[:300])
    if st != 200:
        return ["Rust Helper ping failed: %s %s" % (st, body[:200])]

    with open(a.realshape, encoding="utf-8") as fh:
        sub = fh.read()
    home, prof, _ = make_home(os.path.abspath(a.out), "helperTun", app_dir, sub)
    sid = uuid.uuid4().hex
    pipe = PIPE_PREFIX + sid
    loop = asyncio.get_event_loop()
    host = Host()
    servers = await loop.start_serving_pipe(lambda: host, pipe)
    started = False
    try:
        st, body = helper(a.port, "POST", "/start", {"address": pipe, "sessionId": sid})
        print("start:", st, body[:300])
        if st != 200:
            return ["Helper /start failed: %s %s" % (st, body[:300])]
        started = True
        try:
            await asyncio.wait_for(host.connected, 20)
        except asyncio.TimeoutError:
            return ["core launched by Helper never connected to the pipe"]

        r, dt = await host.call("core.init", {"home-dir": home, "version": 1}, 60)
        print("core.init %.2fs %s" % (dt, short(r, 200)))
        pb, dt = await host.call("profile.base", {"path": prof}, 60)
        cfg = (pb.get("result") or {}).get("config")
        ov = json.loads(dart_like_overlay(cfg, home))
        ov["mode"] = "direct"
        ov["tun"].update({"enable": True, "auto-route": True, "route-address": [],
                          "device": DEVICE})
        args = {"base": {"path": prof, "overlay": json.dumps(ov, ensure_ascii=False)},
                "selected-map": {}, "options": {"test-url": "https://www.gstatic.com/generate_204",
                                                "skip-cert-verify": False,
                                                "delay-test-timeout": 5000, "mitm-capture": False}}
        r, dt = await host.call("config.setup", args, 90)
        print("config.setup %.2fs %s" % (dt, short(r, 300)))
        if r.get("_timeout") or r.get("error"):
            fails.append("config.setup with TUN failed: %s" % short(r, 300))
        r, dt = await host.call("listener.start", None, 60)
        print("listener.start %.2fs %s" % (dt, short(r, 200)))
        if r.get("_timeout") or r.get("error"):
            fails.append("listener.start failed: %s" % short(r, 300))

        status = ""
        for _ in range(30):
            status = adapter_up()
            if status == "Up":
                break
            await asyncio.sleep(1)
        routes = route_count()
        print("adapter %s status=%r routes=%d" % (DEVICE, status, routes))
        rc, out, _ = ps("Get-NetAdapter -IncludeHidden | Format-Table -AutoSize Name,InterfaceDescription,Status | Out-String -Width 200")
        print(out)
        if status != "Up":
            fails.append("TUN adapter %s not Up (status=%r)" % (DEVICE, status))
        if routes < 1:
            fails.append("no routes on TUN adapter")

        targets = [("ip", "http://1.1.1.1/cdn-cgi/trace", "1.1.1.1"),
                   ("domain", "https://www.gstatic.com/generate_204", "gstatic.com")]
        for kind, url, _ in targets:
            code, secs, err = await loop.run_in_executor(None, fetch, url)
            print("fetch %s %s -> %s %.2fs %s" % (kind, url, code, secs, err or ""))
            if code is None or code >= 400:
                fails.append("no-proxy %s request through TUN failed: %s %s" % (kind, code, err))

        cl, _ = await host.call("connection.list", None, 30)
        dump = json.dumps(cl, ensure_ascii=False)
        tt, _ = await host.call("traffic.total", None, 30)
        print("connection.list bytes=%d traffic.total=%s" % (len(dump), short(tt, 200)))
        for kind, _, needle in targets:
            if needle not in dump:
                fails.append("core did not see the %s connection (%s): traffic bypassed TUN" % (kind, needle))
    except ConnectionError as e:
        fails.append("pipe closed: %s" % e)
    finally:
        if started:
            st, body = helper(a.port, "POST", "/stop", {"sessionId": sid})
            print("stop:", st, body[:300])
            if st != 200:
                fails.append("Helper /stop failed: %s %s" % (st, body[:200]))
        try:
            host.transport and host.transport.close()
        except Exception:  # noqa
            pass
        for s in servers:
            s.close()

    gone = False
    for _ in range(30):
        if adapter_up() in ("", "Disconnected", "Not Present") and route_count() == 0:
            gone = True
            break
        await asyncio.sleep(1)
    print("after stop: adapter=%r routes=%d" % (adapter_up(), route_count()))
    if not gone:
        fails.append("TUN adapter or routes left behind after Helper /stop")
    code, secs, err = await loop.run_in_executor(None, fetch, "http://1.1.1.1/cdn-cgi/trace")
    print("network after stop -> %s %s" % (code, err or ""))
    if code is None or code >= 400:
        fails.append("network broken after TUN stop: %s %s" % (code, err))
    return fails


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--app-dir", required=True)
    ap.add_argument("--realshape", required=True)
    ap.add_argument("--out", default="helper-tun-out")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    fails = asyncio.run(run(a))
    print("\nHELPER TUN GATE:", "PASS" if not fails else "FAIL")
    for f in fails:
        print("  - " + f)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    sys.exit(main())
