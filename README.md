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
there). The code is written against Google's current documented SDK
surface (`google-cloud-resource-manager`, `google-cloud-compute`,
`google-genai`), not mocked or faked — but Gemini model names are retired
on Google's own schedule (this project's first default,
`gemini-2.0-flash-001`, was shut down June 1, 2026, mid-build), and the
only way to be sure it works is to run it yourself:

```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
pip install -e ".[ai]"
python scripts/live_smoke_test.py
```

That script checks each layer in order (ADC → IAM API → Compute API →
Gemini) so a failure tells you exactly which one to fix. **Do this before
relying on this in a demo or interview.** Two things already flagged as
uncertain: `collectors/network.py`'s handling of the `Allowed.IPProtocol`
field name (varies across `google-cloud-compute` versions — the smoke test
warns if it can't resolve it), and the Gemini model name in
`ai_detector.py`/`vertex_explainer.py`, which Google updates independently
of this project — check
https://cloud.google.com/vertex-ai/generative-ai/docs/learn/models if you
hit a 404 on the model.

**Note on the SDK itself**: this project uses `google-genai` (`from google
import genai`, `genai.Client(vertexai=True, ...)`), Google's current
unified client. It originally used the older
`vertexai.generative_models.GenerativeModel` interface
(`google-cloud-aiplatform`), which Google deprecated June 24, 2025 and
removed June 24, 2026 — the migration happened during this project's
development, triggered by a live run hitting the deprecation warning
directly. See
https://cloud.google.com/vertex-ai/generative-ai/docs/deprecations/genai-vertexai-sdk
for Google's migration guide.

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
| Storage  | Bucket-level public IAM bindings; distinguishes "public and exploitable" (CRITICAL) from "public binding present but Public Access Prevention enforced" (LOW — dead weight, not currently exploitable). Does not check individual object-level ACLs. |
| Resource hierarchy | IAM bindings inherited from a folder or organization above the project — a project can look locked-down on its own while inheriting `roles/editor` from a folder two levels up. **Best-effort by design**: the scanner service account only has project-level access; reading folder/org policy needs a separate, manually-granted role (see "Required IAM permissions"). Where that's missing, this shows up as its own LOW finding ("couldn't verify inherited IAM") rather than a false all-clear. |

In Gemini mode this is a non-exhaustive starting instruction, not a fixed
list — the model can flag other patterns in the same data too. In
`--rules-only` mode, this list *is* the exhaustive set of checks.

## Architecture

```
                 collectors/iam.py  ──┐
                 collectors/network.py┤
(live GCP APIs)  collectors/storage.py┤
                 collectors/hierarchy.py┤
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

## Automation — running this on a schedule instead of by hand

See [`deploy/terraform/README.md`](deploy/terraform/README.md) for the
manual walkthrough, or
[`deploy/github-actions-setup.md`](deploy/github-actions-setup.md) for
deploying it through a CI/CD pipeline instead (recommended once you're past
the first manual deploy — no local `terraform apply`, keyless GCP auth via
Workload Identity Federation, plan-on-PR/apply-on-merge). Either way: Cloud
Scheduler triggers a Cloud Run Job (containerized via the top-level
`Dockerfile`) on a nightly cron, running as a dedicated least-privilege
service account (no key files), with CRITICAL/HIGH findings posted to
Slack via `--notify-slack`. The scan logic itself doesn't change — this
just wraps the same CLI in infrastructure so nobody has to remember to run
it.

## Required IAM permissions

At minimum, the ADC principal needs:
- `resourcemanager.projects.getIamPolicy`
- `compute.firewalls.list`
- `storage.buckets.list` and `storage.buckets.getIamPolicy`
- `resourcemanager.projects.get` (to walk the ancestor chain)

All of the above are included in the predefined `roles/viewer` role. The
default (Gemini) detection mode and `--explain` additionally need Vertex AI
access (e.g. `roles/aiplatform.user`) and the Vertex AI API enabled on the
project. `--rules-only` needs neither.

**Folder/org-level checks are separate and optional.** By design, the
scanner service account this project provisions only has project-scoped
`roles/viewer` — it can't read folder or organization IAM policy, and
Terraform can't grant itself org-level permissions from a project-scoped
deployment anyway. If you want full inherited-IAM visibility, an org admin
needs to separately grant the scanner service account
`roles/resourcemanager.folderViewer` and/or
`roles/resourcemanager.organizationViewer` at the relevant level. Without
that, the hierarchy check still runs and still reports honestly — it just
reports "couldn't verify" as its own LOW finding rather than silently
skipping it.

## Roadmap / not yet covered

- Cloud Storage: only bucket-level IAM is checked, not individual
  object-level ACLs
- Cloud SQL public IP / backup config
- Cross-project IAM policy inheritance (this only reads the ancestor
  chain of the project being scanned, not sibling projects)
- Egress firewall rules (only ingress is evaluated today)

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
