#!/usr/bin/env python3
"""Run this yourself, against a real GCP project, before a demo or
interview. It is NOT run in CI and NOT covered by `pytest tests/` — see
tests/README.md for why.

Usage:
    gcloud auth application-default login
    gcloud config set project YOUR_PROJECT_ID
    export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
    pip install -e ".[ai]"
    python scripts/live_smoke_test.py

What it checks, step by step, so a failure tells you exactly which layer
broke (auth vs. IAM API vs. Compute API vs. Vertex AI):
"""

import sys


def step(label):
    print(f"\n--- {label} ---")


def main():
    from gcp_live_compliance.auth import check_adc_available, resolve_project_id

    step("1. Application Default Credentials")
    try:
        check_adc_available()
        print("OK — ADC found.")
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    project_id = resolve_project_id(None)
    print(f"Target project: {project_id}")

    step("2. IAM policy (Resource Manager API)")
    try:
        from gcp_live_compliance.collectors.iam import fetch_project_iam_policy

        iam_snapshot = fetch_project_iam_policy(project_id)
        print(f"OK — fetched {len(iam_snapshot.bindings)} IAM binding(s).")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Resource Manager API enabled? Caller has resourcemanager.projects.getIamPolicy?")
        sys.exit(1)

    step("3. Firewall rules (Compute Engine API)")
    try:
        from gcp_live_compliance.collectors.network import fetch_firewall_rules

        fw_rules = fetch_firewall_rules(project_id)
        print(f"OK — fetched {len(fw_rules)} firewall rule(s).")
        if fw_rules:
            sample = fw_rules[0]
            print(f"  Sample rule '{sample.name}': allowed={sample.allowed}")
            print("  ^ If 'protocol' shows as 'unknown', the compute_v1.Allowed field-name "
                  "fallback in collectors/network.py needs a fix for your installed SDK version.")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Compute Engine API enabled? Caller has compute.firewalls.list?")
        sys.exit(1)

    step("4. Gemini-based detection (ai_detector.py — the default mode)")
    try:
        from gcp_live_compliance.ai_detector import detect

        findings = detect(iam_snapshot, fw_rules, project_id)
        print(f"OK — Gemini identified {len(findings)} finding(s) directly from the live data.")
        for f in findings[:3]:
            print(f"  [{f.severity.value}] {f.rule_id}: {f.message}")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Vertex AI API enabled? Model name in ai_detector.py still valid? "
              "Caller has aiplatform access? Did Gemini's response fail to parse as JSON "
              "(see the ValueError text above)?")
        sys.exit(1)

    step("5. Narrative summary (vertex_explainer.py — used by --explain)")
    try:
        from gcp_live_compliance.vertex_explainer import explain

        summary = explain(findings, project_id)
        print("OK — Vertex AI responded:\n")
        print(summary)
    except Exception as exc:
        print(f"FAILED: {exc}")
        sys.exit(1)

    print("\nAll layers confirmed against a live project, including Gemini making the")
    print("actual compliance judgment call. Safe to demo.")


if __name__ == "__main__":
    main()
