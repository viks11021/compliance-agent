"""gcp-live-compliance-agent

Scans a *live* GCP project's IAM policy and VPC firewall configuration for
common misconfigurations, then (optionally) sends the findings to Gemini via
Vertex AI for a plain-English risk summary and remediation plan.

Unlike a static Terraform scanner, this talks to the real GCP APIs
(Cloud Resource Manager, Compute Engine) using Application Default
Credentials, so it reflects what is actually deployed right now, not what is
declared in code.
"""

__version__ = "0.1.0"
