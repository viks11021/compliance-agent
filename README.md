# gcp-live-compliance-agent

Scans a **live** GCP project's IAM policy and VPC firewall configuration.
By default, the actual compliance judgment is made by **Gemini via Vertex
AI** — the model is handed the raw, live IAM bindings and firewall rules
and identifies the issues itself, not just narrates issues a script
already found. A deterministic rule engine is also included as an
explicit `--rules-only` alternative (see "Two detection modes" below).

Companion/successor to
[cloudpolicy-ai](https://github.com/viks11021/cloudpolicy-ai), which scans
Terraform *files* statically. This project checks what's actually deployed
right now, against a real GCP project.

## Two detection modes — and why both exist

| | Default (Gemini) | `--rules-only` |
|---|---|---|
| Who decides what's a finding | Gemini, reasoning over the raw live data | A fixed Python rule set (`rules/iam_rules.py`, `rules/network_rules.py`) |
| Determinism | No — same input can yield a different finding set on a different run | Yes — same input always produces the same output |
| Needs Vertex AI / API cost | Yes | No |
| Catches novel/contextual issues a rule author didn't think of | Potentially | Only what's explicitly coded |
| Can hallucinate a finding that isn't real | Possible | Not possible |

Neither mode is strictly "better" — they're different trade-offs. This
project ships both on purpose, and the honest answer to "does it use AI to
check compliance?" is: **by default, yes — Gemini identifies the findings,
not just summarises them** (see `ai_detector.py`). `--rules-only` exists as
a guaranteed, zero-cost floor for cases (e.g. CI on every commit) where you
want a deterministic check instead.

## Known limitations — read this first

**Neither the Gemini-based detection (`ai_detector.py`) nor the GCP
collector calls have been executed against a live project from the
environment this was built in** (no network path to `*.googleapis.com`
there). The code is written against the documented SDK surface
(`google-cloud-resource-manager`, `google-cloud-compute`,
`google-cloud-aiplatform`), not mocked or faked — but SDK field names and
Gemini model names do shift between versions, and the only way to be sure
it works is to run it yourself:

```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
pip install -e ".[ai]"
python scripts/live_smoke_test.py
```

That script checks each layer in order (ADC → IAM API → Compute API →
Vertex AI) so a failure tells you exactly which one to fix. **Do this
before relying on this in a demo or interview.** One spot already flagged
as uncertain: `collectors/network.py`'s handling of the
`Allowed.IPProtocol` field name, which has varied across
`google-cloud-compute` versions — the smoke test script prints a warning if
it can't resolve it.

The unit tests in `tests/` all use hand-built objects and mocked data —
see `tests/README.md` for exactly what they do and don't prove.

## Quick start

```bash
git clone https://github.com/viks11021/compliance-agent.git
cd compliance-agent
pip install -e ".[ai]"
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID

gcp-live-compliance scan --project YOUR_PROJECT_ID
```

That's Gemini doing the detection by default. For the deterministic,
no-AI-call alternative:

```bash
gcp-live-compliance scan --project YOUR_PROJECT_ID --rules-only
```

Add `--explain` in either mode for a further narrative executive summary
on top of whichever findings were produced.

### CI usage

CI should generally use `--rules-only` — deterministic, free, and doesn't
need Vertex AI credentials in the pipeline:

```bash
gcp-live-compliance scan --project YOUR_PROJECT_ID --rules-only --format json --fail-on CRITICAL --output report.json
```

## What it checks

| Area     | Examples of what either mode looks for |
|----------|-----------------------------------------|
| IAM      | Public bindings (`allUsers` / `allAuthenticatedUsers`), primitive roles (Owner/Editor/Viewer) bound to non-service-account principals |
| Firewall | Sensitive ports (SSH/RDP/common DB ports) or allow-all protocol rules open to `0.0.0.0/0` on ingress |

In Gemini mode this is a non-exhaustive starting instruction, not a fixed
list — the model can flag other patterns in the same data too. In
`--rules-only` mode, this list *is* the exhaustive set of checks.

## Architecture

```
                 collectors/iam.py  ──┐
(live GCP APIs)  collectors/network.py┤
                                       │
                                       ├─→ ai_detector.py (default: Gemini decides findings)
                                       │       — or, with --rules-only —
                                       └─→ rules/*.py (deterministic Finding[])
                                                       │
                                                       ▼
                                        report.py (console/JSON/markdown)
                                                       │
                                                       ▼ (optional, either mode)
                                        vertex_explainer.py (narrative summary)
```

## Required IAM permissions

At minimum, the ADC principal needs:
- `resourcemanager.projects.getIamPolicy`
- `compute.firewalls.list`

These are included in the predefined `roles/viewer` role. The default
(Gemini) detection mode and `--explain` additionally need Vertex AI access
(e.g. `roles/aiplatform.user`) and the Vertex AI API enabled on the
project. `--rules-only` needs neither.

## Roadmap / not yet covered

- Cloud Storage bucket ACLs/IAM (public buckets)
- Cloud SQL public IP / backup config
- Cross-project / org-level policy inheritance (this only reads the
  project's own policy, not inherited folder/org bindings)
- Egress firewall rules (only ingress is evaluated today)

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
