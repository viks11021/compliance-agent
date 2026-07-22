# Test scope — read this before claiming test coverage in an interview

All tests in this directory are **unit tests against hand-built objects**.
None of them call a real GCP API or a real Vertex AI endpoint. Specifically:

- `test_iam_rules.py` / `test_network_rules.py` / `test_storage_rules.py` /
  `test_hierarchy_rules.py` construct `IamPolicySnapshot` /
  `FirewallRuleSnapshot` / `BucketSnapshot` / `HierarchySnapshot` objects
  directly in the test and check the rule functions' output. They prove
  the *rule logic* is correct; they say nothing about whether
  `collectors/iam.py`, `collectors/network.py`, `collectors/storage.py`, or
  `collectors/hierarchy.py` correctly call the real Google APIs, because
  those collectors are never invoked here.
- `test_ai_detector.py` tests `build_prompt()` (does the prompt actually
  contain the live data?) and `parse_response()` (does a JSON string from
  Gemini correctly turn into `Finding` objects, including malformed/fenced
  responses?) using hand-written strings standing in for a Gemini response.
  It does **not** call `detect()`, so it proves nothing about whether the
  real Vertex AI call — the part that actually does the compliance
  judgment — works, or what Gemini's real output looks like.
- `test_vertex_explainer.py` only tests `build_prompt()` for the narrative
  summary layer (`--explain`), same caveat as above.

This was a deliberate choice (unit tests shouldn't need live cloud
credentials to run in CI), not an oversight — but it means green tests here
are **not** evidence that a live scan, a live AI-detection call
(`ai_detector.detect()`), or a live narrative-summary call
(`vertex_explainer.explain()`) works end to end. That can only be
confirmed by running `scripts/live_smoke_test.py` against a real GCP
project with `gcloud auth application-default login` configured. Do that
at least once before you rely on this in a demo or interview — see the
top-level README's "Known limitations" section.
