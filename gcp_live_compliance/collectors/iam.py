"""Fetches the live IAM policy for a GCP project via the Resource Manager API.

Uses google-cloud-resource-manager's ProjectsClient.get_iam_policy, the same
call `gcloud projects get-iam-policy <project>` makes under the hood — this
is a real, authenticated API call against the project you point it at, not a
parsed config file.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class IamBinding:
    role: str
    members: list[str]


@dataclass
class IamPolicySnapshot:
    project_id: str
    bindings: list[IamBinding]


def fetch_project_iam_policy(project_id: str) -> IamPolicySnapshot:
    """Fetch the current IAM policy bindings for `project_id`.

    Requires the caller's ADC identity to have
    `resourcemanager.projects.getIamPolicy` (included in Viewer or above).
    """
    from google.cloud import resourcemanager_v3

    client = resourcemanager_v3.ProjectsClient()
    resource = f"projects/{project_id}"
    policy = client.get_iam_policy(request={"resource": resource})

    bindings = [
        IamBinding(role=b.role, members=list(b.members))
        for b in policy.bindings
    ]
    return IamPolicySnapshot(project_id=project_id, bindings=bindings)
