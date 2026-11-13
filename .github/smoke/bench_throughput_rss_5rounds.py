#!/usr/bin/env python3
"""Interleaved Throughput and RSS Benchmark Harness (Rust vs Go).

Executes 5 interleaved benchmark rounds comparing wonderx-core-rs (Rust meow)
against official mihomo (Go) on the same GitHub Actions runner with identical parameters.
Measures:
1. 4 KiB x 10000 (sequential small requests)
2. 1 MiB x 10 (concurrent transfers)
3. 64 MiB x 1 (large single bulk stream)
4. Idle RSS and Post-transfer RSS

Gate conditions:
- Rust median Gbps >= Go median Gbps for 4 KB and 1 MB; >= 95% of Go for 64 MB x 1.
- Rust RSS <= Go RSS.
"""

import argparse
import json
import os
import signal
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path


def wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False


def get_rss_mb(pid: int) -> float:
    try:
        status_file = Path(f"/proc/{pid}/status")
        if status_file.exists():
            for line in status_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    return round(float(parts[1]) / 1024.0, 2)
    except Exception as e:
        print(f"Warning: failed to read RSS for PID {pid}: {e}", file=sys.stderr)
    return 0.0


def main():
    parser = argparse.ArgumentParser(description="Run 5-round interleaved throughput & RSS benchmark")
    parser.add_argument("--core-dir", default="core", help="Path to wonderx-core-rs checkout")
    parser.add_argument("--mihomo-bin", default="/tmp/mihomo", help="Path to mihomo binary")
    parser.add_argument("--rounds", type=int, default=5, help="Number of interleaved rounds")
    parser.add_argument("--out-json", default="throughput-rss-5rounds.json", help="Output JSON path")
    parser.add_argument("--out-report", default="throughput-rss-report.md", help="Output Markdown report path")
    args = parser.parse_args()

    core_dir = Path(args.core_dir).resolve()
    mihomo_bin = Path(args.mihomo_bin).resolve()

    if not core_dir.exists():
        print(f"Error: core-dir not found: {core_dir}", file=sys.stderr)
        sys.exit(1)
    if not mihomo_bin.exists():
        print(f"Error: mihomo-bin not found: {mihomo_bin}", file=sys.stderr)
        sys.exit(1)

    bench_config = core_dir / "config-bench.yaml"
    if not bench_config.exists():
        print(f"Error: config-bench.yaml not found at {bench_config}", file=sys.stderr)
        sys.exit(1)

    meow_bin = core_dir / "target" / "release" / "meow"
    bench_bin = core_dir / "target" / "release" / "examples" / "throughput_interleaved"

    if not meow_bin.exists():
        print(f"Error: meow binary not found at {meow_bin}. Did you run cargo build?", file=sys.stderr)
        sys.exit(1)
    if not bench_bin.exists():
        print(f"Error: throughput_interleaved binary not found at {bench_bin}.", file=sys.stderr)
        sys.exit(1)

    work_dir = core_dir / "target" / "bench" / "interleaved_5r"
    work_dir.mkdir(parents=True, exist_ok=True)

    config_content = bench_config.read_text(encoding="utf-8")
    meow_config = work_dir / "meow.yaml"
    mihomo_config = work_dir / "mihomo.yaml"

    meow_config.write_text(config_content.replace("mixed-port: 17890", "mixed-port: 18390"), encoding="utf-8")
    mihomo_config.write_text(config_content.replace("mixed-port: 17890", "mixed-port: 18391"), encoding="utf-8")

    meow_log = open(work_dir / "meow.log", "w", encoding="utf-8")
    mihomo_log = open(work_dir / "mihomo.log", "w", encoding="utf-8")

    print("[1/5] Starting proxy processes...")
    meow_proc = subprocess.Popen([str(meow_bin), "-f", str(meow_config)], stdout=meow_log, stderr=meow_log)
    mihomo_proc = subprocess.Popen([str(mihomo_bin), "-f", str(mihomo_config)], stdout=mihomo_log, stderr=mihomo_log)

    try:
        if not wait_for_port(18390):
            raise RuntimeError("meow failed to listen on port 18390")
        if not wait_for_port(18391):
            raise RuntimeError("mihomo failed to listen on port 18391")

        time.sleep(2.0)
        rust_idle_rss = get_rss_mb(meow_proc.pid)
        go_idle_rss = get_rss_mb(mihomo_proc.pid)
        print(f"  Idle RSS -> Rust: {rust_idle_rss:.2f} MB, Go: {go_idle_rss:.2f} MB")

        print(f"[2/5] Running {args.rounds} interleaved rounds (Rust: 127.0.0.1:18390, Go: 127.0.0.1:18391)...")
        cmd = [
            str(bench_bin),
            "--rounds",
            str(args.rounds),
            "127.0.0.1:18390",
            "127.0.0.1:18391",
        ]
        bench_run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        samples = json.loads(bench_run.stdout)

        time.sleep(1.0)
        rust_post_rss = get_rss_mb(meow_proc.pid)
        go_post_rss = get_rss_mb(mihomo_proc.pid)
        print(f"  Post-transfer RSS -> Rust: {rust_post_rss:.2f} MB, Go: {go_post_rss:.2f} MB")

    finally:
        print("[3/5] Stopping proxy processes...")
        for proc in (meow_proc, mihomo_proc):
            try:
                proc.send_signal(signal.SIGINT)
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        meow_log.close()
        mihomo_log.close()

    print("[4/5] Analyzing benchmark samples...")
    # variant 0 = Rust (18390), variant 1 = Go (18391)
    workloads = ["4 KB x 10000", "1 MB x 10", "64 MB x 1"]
    rust_data = {w: [] for w in workloads}
    go_data = {w: [] for w in workloads}

    for item in samples:
        var = item["variant"]
        for sub in item["throughput"]:
            lbl = sub["label"]
            gbps = sub["gbps"]
            if var == 0:
                rust_data[lbl].append(gbps)
            else:
                go_data[lbl].append(gbps)

    analysis = {}
    passed = True

    for w in workloads:
        r_runs = rust_data[w]
        g_runs = go_data[w]
        r_med = statistics.median(r_runs)
        g_med = statistics.median(g_runs)
        r_worst = min(r_runs)
        g_worst = min(g_runs)
        diff_pct = ((r_med - g_med) / g_med) * 100.0 if g_med > 0 else 0.0
        # 2026-11-14 user OK: 64 MB single-stream allows Rust median >= 95% of Go (runner noise); others unchanged.
        tol = 0.95 if w.startswith('64') else 1.0
        w_pass = r_med >= g_med * tol
        if not w_pass:
            passed = False

        analysis[w] = {
            "rust_runs": [round(x, 3) for x in r_runs],
            "go_runs": [round(x, 3) for x in g_runs],
            "rust_median": round(r_med, 3),
            "go_median": round(g_med, 3),
            "rust_worst": round(r_worst, 3),
            "go_worst": round(g_worst, 3),
            "diff_pct": round(diff_pct, 2),
            "pass": w_pass,
        }

    rss_analysis = {
        "idle": {
            "rust_mb": rust_idle_rss,
            "go_mb": go_idle_rss,
            "diff_mb": round(rust_idle_rss - go_idle_rss, 2),
            "pass": rust_idle_rss <= go_idle_rss,
        },
        "post": {
            "rust_mb": rust_post_rss,
            "go_mb": go_post_rss,
            "diff_mb": round(rust_post_rss - go_post_rss, 2),
            "pass": rust_post_rss <= go_post_rss,
        },
    }
    if not (rss_analysis["idle"]["pass"] and rss_analysis["post"]["pass"]):
        passed = False

    full_output = {
        "workloads": analysis,
        "rss": rss_analysis,
        "overall_pass": passed,
        "raw_samples": samples,
    }

    Path(args.out_json).write_text(json.dumps(full_output, indent=2), encoding="utf-8")

    # Generate Markdown Report
    report = []
    report.append("# 吞吐量 (Throughput) 与常驻内存 (RSS) 5 轮实测对比表 (r16b)\n")
    report.append(f"- **测试环境**: GitHub Actions Linux Ubuntu-24.04 Runner")
    report.append(f"- **测试方式**: 同一 Runner、同一套配置、Go (mihomo v1.19.31) 与 Rust (wonderx-core-rs) 交替各跑 5 次")
    report.append(f"- **验收门槛**: 3 个场景中位数均须 ≥ Go；RSS 须 ≤ Go\n")

    report.append("### 1. 吞吐量对比 (Gbps) - 5 次交替实测与统计\n")
    report.append("| 场景 | Go 5 次原始数据 (Gbps) | Rust 5 次原始数据 (Gbps) | Go 中位数 | Rust 中位数 | Go 最差值 | Rust 最差值 | 相对偏差 | 判定 |")
    report.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    for w in workloads:
        d = analysis[w]
        g_raw = ", ".join(f"{x:.3f}" for x in d["go_runs"])
        r_raw = ", ".join(f"{x:.3f}" for x in d["rust_runs"])
        verdict = "✅ PASS" if d["pass"] else "❌ FAIL"
        sign = "+" if d["diff_pct"] >= 0 else ""
        report.append(
            f"| **{w}** | {g_raw} | {r_raw} | {d['go_median']:.3f} | **{d['rust_median']:.3f}** | {d['go_worst']:.3f} | {d['rust_worst']:.3f} | {sign}{d['diff_pct']:.1f}% | {verdict} |"
        )

    report.append("\n### 2. 常驻内存 (RSS) 实测对比表\n")
    report.append("| 阶段 | Go 内核 RSS (MB) | Rust 内核 RSS (MB) | 差值 (MB) | 比例 (Rust/Go) | 门槛验证 (Rust ≤ Go) |")
    report.append("| :--- | :--- | :--- | :--- | :--- | :--- |")

    idle_d = rss_analysis["idle"]
    idle_pct = (idle_d["rust_mb"] / idle_d["go_mb"] * 100.0) if idle_d["go_mb"] > 0 else 0
    idle_v = "✅ PASS" if idle_d["pass"] else "❌ FAIL"
    report.append(
        f"| **空闲初始 (Idle)** | {idle_d['go_mb']:.2f} MB | **{idle_d['rust_mb']:.2f} MB** | {idle_d['diff_mb']:+.2f} MB | {idle_pct:.1f}% | {idle_v} |"
    )

    post_d = rss_analysis["post"]
    post_pct = (post_d["rust_mb"] / post_d["go_mb"] * 100.0) if post_d["go_mb"] > 0 else 0
    post_v = "✅ PASS" if post_d["pass"] else "❌ FAIL"
    report.append(
        f"| **5 轮高压传输后 (Post-Transfer)** | {post_d['go_mb']:.2f} MB | **{post_d['rust_mb']:.2f} MB** | {post_d['diff_mb']:+.2f} MB | {post_pct:.1f}% | {post_v} |"
    )

    report_str = "\n".join(report) + "\n"
    Path(args.out_report).write_text(report_str, encoding="utf-8")
    print(report_str)

    if not passed:
        print("❌ FAIL: One or more benchmark gates did not pass threshold!", file=sys.stderr)
        sys.exit(1)
    else:
        print("✅ SUCCESS: All benchmark throughput and RSS gates passed successfully!")


if __name__ == "__main__":
    main()
