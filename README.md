# gcp-live-compliance-agent

Scans a **live** GCP project's IAM policy and VPC firewall configuration for
common misconfigurations, using the real Resource Manager and Compute
Engine APIs against Application Default Credentials — not a static
Terraform parser. Optionally sends the findings to **Gemini via Vertex AI**
for a plain-English risk summary.

Companion/successor to
[cloudpolicy-ai](https://github.com/viks11021/cloudpolicy-ai), which scans
Terraform *files* statically. This project checks what's actually deployed
right now.

## Known limitations — read this first

**The Vertex AI call and the two GCP collector calls have not been executed
against a live project from the environment this was built in** (no
network path to `*.googleapis.com` there). The code is written against the
documented SDK surface (`google-cloud-resource-manager`,
`google-cloud-compute`, `google-cloud-aiplatform`), not mocked or faked —
but SDK field names and Gemini model names do shift between versions, and
the only way to be sure it works is to run it yourself:

```bash
gcloud auth application-default login
gcloud config set project YOUR_PROJECT_ID
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID
pip install -e ".[ai]"
python scripts/live_smoke_test.py
```

That script checks each layer in order (ADC → IAM API → Compute API →
Vertex AI) so a failure tells you exactly which one to fix. **Do this
before relying on `--explain` in a demo or interview.** One spot already
flagged as uncertain: `collectors/network.py`'s handling of the
`Allowed.IPProtocol` field name, which has varied across
`google-cloud-compute` versions — the smoke test script prints a warning if
it can't resolve it.

The unit tests in `tests/` all use hand-built objects and mocked data —
see `tests/README.md` for exactly what they do and don't prove.

## Quick start

```bash
git clone https://github.com/<your-username>/gcp-live-compliance-agent.git
cd gcp-live-compliance-agent
pip install -e .

gcp-live-compliance scan --project YOUR_PROJECT_ID
```

### With the Vertex AI explanation layer

```bash
pip install -e ".[ai]"
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=YOUR_PROJECT_ID

gcp-live-compliance scan --project YOUR_PROJECT_ID --explain
```

`--explain` is optional — a plain scan needs only IAM/Compute read access,
not the Vertex AI API.

### CI usage

```bash
gcp-live-compliance scan --project YOUR_PROJECT_ID --format json --fail-on CRITICAL --output report.json
```

## What it checks

| Area     | Rules |
|----------|-------|
| IAM      | Public bindings (`allUsers` / `allAuthenticatedUsers`), primitive roles (Owner/Editor/Viewer) bound to non-service-account principals |
| Firewall | Sensitive ports (SSH/RDP/common DB ports) or allow-all protocol rules open to `0.0.0.0/0` on ingress |

Both are intentionally narrow, high-signal checks to start from — see
"Roadmap" below for what's deliberately not covered yet.

## Architecture

```
                 collectors/iam.py  ──┐
(live GCP APIs)  collectors/network.py┼─→ rules/*.py → Finding[] → report.py (console/JSON/markdown)
                                       │                                │
                                       │                                ▼
                                       └──────────────────→ vertex_explainer.py
                                                              (optional, real Vertex AI call)
```

## Required IAM permissions

To run a plain scan, the ADC principal needs, at minimum:
- `resourcemanager.projects.getIamPolicy`
- `compute.firewalls.list`

These are included in the predefined `roles/viewer` role. `--explain`
additionally needs Vertex AI access (e.g. `roles/aiplatform.user`) and the
Vertex AI API enabled on the project.

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
