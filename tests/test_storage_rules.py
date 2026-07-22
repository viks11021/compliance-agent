"""Unit tests for storage_rules — hand-built BucketSnapshot objects, no
live Storage API calls."""

from gcp_live_compliance.collectors.storage import BucketSnapshot
from gcp_live_compliance.rules import storage_rules


def test_flags_public_bucket_no_pap():
    bucket = BucketSnapshot(
        name="my-public-bucket",
        bindings=[{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        public_access_prevention=None,
    )
    findings = storage_rules.evaluate([bucket])
    assert any(f.rule_id == "STORAGE_PUBLIC_BUCKET" for f in findings)


def test_public_binding_with_pap_enforced_is_low_not_critical():
    bucket = BucketSnapshot(
        name="my-bucket",
        bindings=[{"role": "roles/storage.objectViewer", "members": ["allUsers"]}],
        public_access_prevention="enforced",
    )
    findings = storage_rules.evaluate([bucket])
    assert len(findings) == 1
    assert findings[0].rule_id == "STORAGE_PUBLIC_BINDING_BUT_PAP_ENFORCED"
    assert findings[0].severity.value == "LOW"


def test_clean_bucket_no_findings():
    bucket = BucketSnapshot(
        name="my-bucket",
        bindings=[{"role": "roles/storage.objectViewer", "members": ["group:team@example.com"]}],
        public_access_prevention="enforced",
    )
    assert storage_rules.evaluate([bucket]) == []


def test_all_authenticated_users_also_flagged():
    bucket = BucketSnapshot(
        name="my-bucket",
        bindings=[{"role": "roles/storage.objectViewer", "members": ["allAuthenticatedUsers"]}],
        public_access_prevention=None,
    )
    findings = storage_rules.evaluate([bucket])
    assert any(f.rule_id == "STORAGE_PUBLIC_BUCKET" for f in findings)
