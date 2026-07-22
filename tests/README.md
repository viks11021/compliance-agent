# Test scope — read this before claiming test coverage in an interview

All tests in this directory are **unit tests against hand-built objects**.
None of them call a real GCP API or a real Vertex AI endpoint. Specifically:

- `test_iam_rules.py` / `test_network_rules.py` construct
  `IamPolicySnapshot` / `FirewallRuleSnapshot` objects directly in the test
  and check the rule functions' output. They prove the *rule logic* is
  correct; they say nothing about whether `collectors/iam.py` or
  `collectors/network.py` correctly call the real Google APIs, because
  those collectors are never invoked here.
- `test_vertex_explainer.py` only tests `build_prompt()`, a pure string
  function. It does **not** call `explain()`, so it proves nothing about
  whether the real Vertex AI call in `vertex_explainer.explain()` actually
  works.

This was a deliberate choice (unit tests shouldn't need live cloud
credentials to run in CI), not an oversight — but it means green tests here
are **not** evidence that a live scan or a live Gemini call works end to
end. That can only be confirmed by running `scripts/live_smoke_test.py`
against a real GCP project with `gcloud auth application-default login`
configured. Do that at least once before you rely on this in a demo or
interview — see the top-level README's "Known limitations" section.
