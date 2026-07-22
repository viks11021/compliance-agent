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
broke (auth vs. IAM API vs. Compute API vs. Storage API vs. resource
hierarchy vs. Vertex AI):
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

    step("4. Storage bucket IAM policies (Storage API)")
    try:
        from gcp_live_compliance.collectors.storage import fetch_bucket_iam_policies

        buckets = fetch_bucket_iam_policies(project_id)
        print(f"OK — fetched IAM policy for {len(buckets)} bucket(s).")
        if buckets:
            print(f"  Sample: '{buckets[0].name}', public_access_prevention={buckets[0].public_access_prevention}")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Storage API enabled? Caller has storage.buckets.list/getIamPolicy?")
        sys.exit(1)

    step("5. Resource hierarchy (folder/org ancestor IAM policies)")
    try:
        from gcp_live_compliance.collectors.hierarchy import fetch_resource_hierarchy

        hierarchy = fetch_resource_hierarchy(project_id)
        print(f"OK — has_organization={hierarchy.has_organization}, {len(hierarchy.ancestors)} ancestor(s) walked.")
        for a in hierarchy.ancestors:
            status = f"ERROR: {a.error}" if a.error else f"{len(a.bindings)} binding(s) read"
            print(f"  {a.resource_type} {a.resource_name}: {status}")
        print("  ^ An ERROR here for folder/org levels is EXPECTED unless an org admin has")
        print("    separately granted the scanner service account folder/org viewer access —")
        print("    see collectors/hierarchy.py's docstring. Not a failure of this step.")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Caller has resourcemanager.projects.get? (This is the project's own")
        print("ancestor lookup, not the folder/org policy reads — those failing is expected,")
        print("this failing is not.)")
        sys.exit(1)

    step("6. Gemini-based detection (ai_detector.py — the default mode)")
    try:
        from gcp_live_compliance.ai_detector import detect

        findings = detect(iam_snapshot, fw_rules, project_id, buckets=buckets, hierarchy=hierarchy)
        print(f"OK — Gemini identified {len(findings)} finding(s) directly from the live data.")
        for f in findings[:3]:
            print(f"  [{f.severity.value}] {f.rule_id}: {f.message}")
    except Exception as exc:
        print(f"FAILED: {exc}")
        print("Check: Vertex AI API enabled? Caller has aiplatform access? Is the model name in "
              "ai_detector.py still live (Google retires Gemini model versions on their own "
              "schedule — check https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models)? "
              "Did Gemini's response fail to parse as JSON (see the ValueError text above)?")
        sys.exit(1)

    step("7. Narrative summary (vertex_explainer.py — used by --explain)")
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
