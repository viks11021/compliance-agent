"""Shared data model for findings, independent of where they came from
(IAM collector, network collector, future collectors)."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    resource_type: str          # e.g. "iam_policy", "firewall_rule"
    resource_name: str          # e.g. "projects/my-proj", "fw-allow-ssh"
    message: str
    recommendation: str
    raw: dict = field(default_factory=dict)  # original API object, for --explain / debugging
    source: str = "rules"        # "rules" (deterministic) or "ai" (Gemini-detected)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "message": self.message,
            "recommendation": self.recommendation,
            "source": self.source,
        }
