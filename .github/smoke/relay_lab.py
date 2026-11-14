#!/usr/bin/env python3
"""Relay lab: run several meow variants and mihomo copies side by side, N interleaved rounds, print medians."""
import json, os, signal, socket, statistics, subprocess, sys, time
from pathlib import Path
core = Path(sys.argv[1]).resolve(); mihomo = sys.argv[2]; rounds = sys.argv[3]
groups = json.loads(sys.argv[4])  # list of lists of variant names
variants = json.loads(sys.argv[5])  # name -> {"kind":"meow"|"go","env":{...}}
meow = core/"target/release/meow"; bench = core/"target/release/examples/throughput_interleaved"
cfg = (core/"config-bench.yaml").read_text()
wd = core/"target/lab"; wd.mkdir(parents=True, exist_ok=True)
def wait(port):
    for _ in range(100):
        try: socket.create_connection(("127.0.0.1", port), 0.2).close(); return True
        except OSError: time.sleep(0.1)
    return False
procs = {}; ports = {}
for i, (name, v) in enumerate(variants.items()):
    port = 18400 + i; ports[name] = port
    c = wd/f"{name}.yaml"; c.write_text(cfg.replace("mixed-port: 17890", f"mixed-port: {port}"))
    env = dict(os.environ); env.update(v.get("env", {}))
    binp = str(meow) if v["kind"] == "meow" else mihomo
    args = [binp, "-f", str(c)]
    procs[name] = subprocess.Popen(args, env=env, stdout=open(wd/f"{name}.log","w"), stderr=subprocess.STDOUT)
try:
    for n, p in ports.items():
        if not wait(p): raise SystemExit(f"{n} did not listen")
    time.sleep(1)
    report = {}
    for g in groups:
        out = subprocess.run([str(bench), "--rounds", rounds] + [f"127.0.0.1:{ports[n]}" for n in g],
                             capture_output=True, text=True, check=True).stdout
        for s in json.loads(out):
            name = g[s["variant"]]
            for t in s["throughput"]:
                report.setdefault(t["label"], {}).setdefault(f"{name}@{'+'.join(g)}", []).append(t["gbps"])
    for label, d in report.items():
        print(f"\n== {label} ==")
        for k, v in d.items():
            print(f"  {k:55s} median {statistics.median(v):7.3f}  min {min(v):7.3f}  max {max(v):7.3f}")
    Path("lab-report.json").write_text(json.dumps(report, indent=1))
finally:
    for p in procs.values():
        p.send_signal(signal.SIGINT)
        try: p.wait(3)
        except Exception: p.kill()
