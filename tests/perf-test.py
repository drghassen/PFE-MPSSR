#!/usr/bin/env python3
import json
import os
import time

def generate_massive_report(num_findings=50000):
    print(f"[*] Generating {num_findings} dummy findings for Trivy...")
    findings = []

    for i in range(num_findings):
        severity = "MEDIUM"
        if i % 100 == 0: severity = "CRITICAL"
        elif i % 10 == 0: severity = "HIGH"

        findings.append({
            "id": f"CVE-2024-{i:05d}",
            "description": f"Dummy vulnerability #{i} for performance testing.",
            "severity": {"level": severity},
            "resource": {"name": f"lib-dummy-{i}", "path": f"/usr/lib/lib-dummy-{i}.so"},
            "status": "FAILED",
            "category": "VULNERABILITIES"
        })

    report = {
        "tool": "trivy",
        "version": "perf-test-1.0",
        "status": "FAILED",
        "stats": {
            "TOTAL": num_findings
        },
        "findings": findings
    }

    out_dir = ".cloudsentinel"
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "trivy_opa.json"), "w") as f:
        json.dump(report, f)

    # Create empty ones for Gitleaks and Checkov so the normalizer doesn't complain
    empty_report = {"status": "NOT_RUN", "findings": []}
    with open(os.path.join(out_dir, "gitleaks_opa.json"), "w") as f:
        json.dump(empty_report, f)
    with open(os.path.join(out_dir, "checkov_opa.json"), "w") as f:
        json.dump(empty_report, f)

    print(f"[*] Done writing to {out_dir}")

if __name__ == "__main__":
    generate_massive_report(50000)

    print("\n[*] Starting Python Normalizer on 50,000 findings...")
    start_time = time.time()

    # Execute the normalizer
    os.system("python3 shift-left/normalizer/normalize.py > /dev/null")

    end_time = time.time()
    duration = (end_time - start_time) * 1000

    print(f"\n[+] Normalization Complete!")
    print(f"[+] Total execution time: {duration:.2f} ms")

    # Check the output file size
    size_mb = os.path.getsize(".cloudsentinel/golden_report.json") / (1024 * 1024)
    print(f"[+] Output Golden Report size: {size_mb:.2f} MB")

    if duration < 5000:
        print("\n[VERDICT] PASSED - Enterprise-grade performance (under 5s for 50k findings)")
    else:
        print("\n[VERDICT] FAILED - Too slow")
