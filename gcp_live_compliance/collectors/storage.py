"""Fetches live IAM policies and public-access settings for every Cloud
Storage bucket in a project, via the real Storage API — same call
`gsutil iam get gs://bucket` / the Storage console's Permissions tab make.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BucketSnapshot:
    name: str
    bindings: list[dict]  # [{"role": "roles/storage.objectViewer", "members": [...]}, ...]
    # 'enforced' | 'inherited' | None — GCS's own belt-and-braces setting that
    # blocks public ACLs/IAM regardless of what's granted, when enforced.
    public_access_prevention: str | None = None


def fetch_bucket_iam_policies(project_id: str) -> list[BucketSnapshot]:
    """Fetch IAM policy + public access prevention setting for every bucket
    in `project_id`.

    Requires the caller's ADC identity to have `storage.buckets.list` and
    `storage.buckets.getIamPolicy` (both included in the predefined Viewer
    role). Individual object-level ACLs are NOT checked — a bucket could
    still expose specific objects via legacy per-object ACLs even with a
    locked-down bucket-level IAM policy; that's out of scope here (see the
    top-level README's Roadmap section).
    """
    from google.cloud import storage

    client = storage.Client(project=project_id)
    snapshots: list[BucketSnapshot] = []

    for bucket in client.list_buckets():
        policy = bucket.get_iam_policy(requested_policy_version=3)
        bindings = [
            {"role": role, "members": sorted(policy[role])} for role in policy
        ]

        pap = None
        try:
            pap = bucket.iam_configuration.public_access_prevention
        except AttributeError:
            # Defensive: older google-cloud-storage versions structure this
            # differently. Not verified live from the sandbox this was
            # written in — if this stays None unexpectedly, check the
            # installed library version's IAMConfiguration shape.
            pass

        snapshots.append(
            BucketSnapshot(name=bucket.name, bindings=bindings, public_access_prevention=pap)
        )

    return snapshots
