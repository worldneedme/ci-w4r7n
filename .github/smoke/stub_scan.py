#!/usr/bin/env python3
"""
stub_scan.py: Zero-Stub CI Gate for WONDERX Desktop and Mobile IPC dispatchers.

Scans wonderx-desktop and wonderx-mobile dispatch.rs match arms against
FlClash Go protocol.go methods. Any method that Go implements with real logic
must not return a dummy constant (Value::Null, json!([]), json!({}), etc.).

Approved whitelist per Hark review rules:
- core.gc: Go runtime.GC() action returning null (method.go:187)
- profile.clearEffect: Go handleClearEffect command returning null (method.go:199, provider.go:315)
- listener.start / listener.stop: (Mobile only) Android uses VpnService tun fd, no TCP listener
- mitm.*: Go returns null when mitm not enabled (method.go:75-82)
"""

import sys
import os
import re

APPROVED_WHITELIST = {
    "core.gc": "Go action(handleForceGC) calls runtime.GC() and returns null (client/core/method.go:187)",
    "profile.clearEffect": "Go command(handleClearEffect) removes cached files and returns null (client/core/method.go:199, provider.go:315)",
    "mitm.certificate": "Go mitm disabled returns null (client/core/method.go:75)",
    "mitm.generateCertificate": "Go mitm disabled returns null (client/core/method.go:76)",
    "mitm.validate": "Go mitm disabled returns null (client/core/method.go:77)",
    "mitm.issueCertificate": "Go mitm disabled returns null (client/core/method.go:78)",
    "mitm.runScript": "Go mitm disabled returns null (client/core/method.go:79)",
    "mitm.exchanges": "Go mitm disabled returns null (client/core/method.go:80)",
    "mitm.exchange": "Go mitm disabled returns null (client/core/method.go:81)",
    "mitm.body": "Go mitm disabled returns null (client/core/method.go:82)",
}

# Mobile-specific allowed items
MOBILE_WHITELIST = dict(APPROVED_WHITELIST, **{
    "listener.start": "Mobile uses Android VpnService tun fd; no desktop TCP listener (client/core/hub.go:startListener)",
    "listener.stop": "Mobile uses Android VpnService tun fd; no desktop TCP listener (client/core/hub.go:stopListener)",
})

# Suspicious dummy constant return patterns
DUMMY_PATTERNS = [
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*Value::Null\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*\[\s*\]\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*\{\s*\}\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*""\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*0\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*\{[^}]*"ip":\s*"0\.0\.0\.0"[^}]*\}\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*\{[^}]*"defaultInterface":[^}]*\}\s*\)\s*\)'),
    re.compile(r'MethodResponse::success\s*\(\s*id\s*,\s*json!\s*\(\s*\{[^}]*"rss":\s*0[^}]*\}\s*\)\s*\)'),
]

def scan_file(filepath: str) -> list:
    is_mobile = "mobile" in filepath.lower()
    whitelist = MOBILE_WHITELIST if is_mobile else APPROVED_WHITELIST
    violations = []

    with open(filepath, "r", encoding="utf-8") as fh:
        content = fh.read()

    # Find dispatch_inner match block
    match_start = content.find("match method {")
    if match_start == -1:
        match_start = content.find("match call.method.as_str() {")
    if match_start == -1:
        violations.append(f"{filepath}: could not find dispatch match block")
        return violations

    block = content[match_start:]
    # Match arms of format "method.name" => { ... } or "method.name" => expr,
    arm_regex = re.compile(r'^\s*"([a-zA-Z0-9_\.]+)"\s*=>\s*(.+?)(?=^\s*"(?:[a-zA-Z0-9_\.]+)"\s*=>|^\s*m if|^\s*unknown\s*=>|\Z)', re.MULTILINE | re.DOTALL)

    for m in arm_regex.finditer(block):
        method_name = m.group(1)
        body = m.group(2).strip()

        if method_name in whitelist:
            continue

        # Check if body directly returns a dummy constant without calling any service/tracker/manager logic
        has_real_call = any(kw in body for kw in [
            "wonderx_service::",
            "state.traffic_manager.",
            "state.log_broadcaster.",
            "state.route_tracker.",
            "handle_",
            "restart_listener",
            "start_tun",
            "stop_tun",
        ])

        if not has_real_call:
            for pat in DUMMY_PATTERNS:
                if pat.search(body):
                    violations.append(f"{filepath}: method '{method_name}' is a stub returning constant dummy value:\n  {body[:150]}")
                    break

    return violations

def main():
    if len(sys.argv) < 2:
        print("Usage: stub_scan.py <path/to/dispatch.rs> [...]")
        sys.exit(1)

    all_violations = []
    for path in sys.argv[1:]:
        if not os.path.exists(path):
            print(f"Error: file not found: {path}")
            sys.exit(1)
        v = scan_file(path)
        all_violations.extend(v)

    if all_violations:
        print("❌ STUB-SCAN GATE FAILED: Stubs detected in IPC dispatchers!")
        for viol in all_violations:
            print(viol)
        sys.exit(1)
    else:
        print("✅ STUB-SCAN GATE PASSED: Zero stubs detected across all checked dispatchers.")
        sys.exit(0)

if __name__ == "__main__":
    main()
