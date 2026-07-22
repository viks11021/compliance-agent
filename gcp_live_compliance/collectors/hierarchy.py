"""Walks the resource hierarchy above a project (project -> folder(s) ->
organization) and attempts to read IAM policy at each level.

Why this matters: `collectors/iam.py` only reads the PROJECT's own IAM
policy. But GCP's *effective* permissions on a project are the project's
own bindings PLUS everything inherited from every folder and the org above
it. A project can look locked-down at its own level while a folder two
levels up grants `roles/editor` to a whole group — invisible unless you
walk the hierarchy and check each level, which is exactly what this does.

HONEST LIMITATION, not a bug to fix later: the scanner's service account
is deliberately scoped to `roles/viewer` at the PROJECT level only (see
deploy/terraform/main.tf) — it has no folder- or org-level role by
default, and granting one requires an org admin's action outside of what
this project's own Terraform can do (a project-scoped deployment can't
grant itself org-level permissions). So in the common case, folder/org
policy reads here will fail with PERMISSION_DENIED — and this module
reports that honestly as a finding of its own ("couldn't verify inherited
IAM — here's why") rather than silently returning an empty, falsely-clean
result. If you want full hierarchy visibility, an org admin needs to grant
the scanner service account `roles/resourcemanager.folderViewer` and/or
`roles/resourcemanager.organizationViewer` at the relevant folder/org —
that's a deliberate, manual, out-of-band decision, not something this tool
grants itself.

Also worth knowing: plenty of GCP projects — including ones created
without a Google Workspace/Cloud Identity org, which is common for
personal or demo projects — have NO organization at all. In that case
there's nothing above the project to check, and this module reports that
too, distinctly from a permission failure.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class AncestorPolicy:
    resource_name: str  # e.g. "folders/123456789" or "organizations/987654321"
    resource_type: str  # "folder" | "organization"
    bindings: list[dict] = field(default_factory=list)
    error: str | None = None  # set if the policy read failed (e.g. permission denied)


@dataclass
class HierarchySnapshot:
    project_id: str
    ancestors: list[AncestorPolicy] = field(default_factory=list)
    has_organization: bool = False


def _walk_ancestors(project_id: str) -> list[str]:
    """Returns ancestor resource names from immediate parent up to the org,
    e.g. ["folders/111", "folders/222", "organizations/333"]. Empty list if
    the project has no parent (shouldn't normally happen) or sits directly
    under an org with no folders."""
    from google.cloud import resourcemanager_v3

    projects_client = resourcemanager_v3.ProjectsClient()
    project = projects_client.get_project(name=f"projects/{project_id}")

    ancestors: list[str] = []
    current = project.parent  # e.g. "folders/111" or "organizations/333" or None

    if not current:
        return ancestors

    folders_client = None
    while current:
        ancestors.append(current)
        if current.startswith("organizations/"):
            break  # top of the hierarchy, no further parent
        if current.startswith("folders/"):
            if folders_client is None:
                folders_client = resourcemanager_v3.FoldersClient()
            folder = folders_client.get_folder(name=current)
            current = folder.parent
        else:
            break  # unrecognized resource type, stop rather than guess

    return ancestors


def fetch_resource_hierarchy(project_id: str) -> HierarchySnapshot:
    """Fetch the project's ancestor chain and attempt an IAM policy read at
    each level. Never raises on a permission failure at the folder/org
    level — that's an expected, reportable outcome, not an error that
    should crash the scan. A genuine failure to even read the project's own
    ancestor chain (e.g. resourcemanager.projects.get denied) DOES raise,
    since that's a more fundamental setup problem than the expected
    folder/org access gap.
    """
    from google.api_core.exceptions import PermissionDenied
    from google.cloud import resourcemanager_v3

    ancestor_names = _walk_ancestors(project_id)
    snapshot = HierarchySnapshot(
        project_id=project_id,
        has_organization=any(a.startswith("organizations/") for a in ancestor_names),
    )

    folders_client = None
    orgs_client = None

    for name in ancestor_names:
        resource_type = "organization" if name.startswith("organizations/") else "folder"
        try:
            if resource_type == "folder":
                if folders_client is None:
                    folders_client = resourcemanager_v3.FoldersClient()
                policy = folders_client.get_iam_policy(request={"resource": name})
            else:
                if orgs_client is None:
                    orgs_client = resourcemanager_v3.OrganizationsClient()
                policy = orgs_client.get_iam_policy(request={"resource": name})

            bindings = [
                {"role": b.role, "members": list(b.members)} for b in policy.bindings
            ]
            snapshot.ancestors.append(
                AncestorPolicy(resource_name=name, resource_type=resource_type, bindings=bindings)
            )
        except PermissionDenied as exc:
            snapshot.ancestors.append(
                AncestorPolicy(
                    resource_name=name,
                    resource_type=resource_type,
                    error=(
                        f"Permission denied reading IAM policy at {name}: {exc}. "
                        "This is expected unless an org admin has separately "
                        "granted the scanner service account folder/org-level "
                        "viewer access — see this module's docstring."
                    ),
                )
            )

    return snapshot
