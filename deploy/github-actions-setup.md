# One-time setup: GitHub Actions → GCP (Workload Identity Federation)

Run this once, by hand, from your machine (the same place you ran the
manual `terraform apply` earlier). After this, the pipeline authenticates
itself — no static key, nothing to rotate or leak in a repo secret.

## Step 0: move state to GCS first (do this before anything else here)

Right now your Terraform state is a local file on your laptop. A GitHub
Actions runner starts fresh every time and has no access to it — without
this step, the pipeline's first `terraform apply` would try to recreate
every resource you already deployed and fail with "already exists"
errors.

```bash
PROJECT_ID=cloudpolicy-ai-demo
BUCKET="${PROJECT_ID}-tfstate"

gcloud storage buckets create "gs://${BUCKET}" \
  --project="$PROJECT_ID" --location=us-central1 \
  --uniform-bucket-level-access

# Enables versioning so a bad apply's state is recoverable, not just overwritten
gcloud storage buckets update "gs://${BUCKET}" --versioning
```

`deploy/terraform/backend.hcl` already points at
`cloudpolicy-ai-demo-tfstate` — edit it if you used a different bucket
name. Then, from `deploy/terraform/`, migrate your *existing* local state
into it:

```bash
cd deploy/terraform
terraform init -backend-config=backend.hcl -migrate-state
```

Terraform will ask to confirm copying state to the new backend — say yes.
Run `terraform plan` again afterward with your usual `-var` flags; it
should show **0 to add, 0 to change, 0 to destroy** if the migration
worked, since nothing actually changed, only where the state lives.

## Why WIF instead of a service account key

A downloaded JSON key is a long-lived credential sitting in GitHub's
secret store — if it leaks, it's valid until someone manually revokes it.
Workload Identity Federation lets GitHub's own OIDC token (already
short-lived, already scoped to this specific repo and workflow) directly
authenticate as a GCP service account, with no key material anywhere. This
is the same principle as the GitHub Actions-to-AWS OIDC pattern — just
GCP's version of it.

## Steps

```bash
PROJECT_ID=cloudpolicy-ai-demo
PROJECT_NUMBER=$(gcloud projects describe $PROJECT_ID --format="value(projectNumber)")
GITHUB_REPO="viks11021/compliance-agent"   # exact owner/repo, case-sensitive

# 1. A pool to hold external (non-Google) identities
gcloud iam workload-identity-pools create "github-pool" \
  --project="$PROJECT_ID" \
  --location="global" \
  --display-name="GitHub Actions pool"

# 2. A provider inside that pool, trusting GitHub's OIDC tokens —
#    restricted to this specific repo via the attribute-condition
gcloud iam workload-identity-pools providers create-oidc "github-provider" \
  --project="$PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="github-pool" \
  --display-name="GitHub provider" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
  --attribute-condition="assertion.repository=='${GITHUB_REPO}'" \
  --issuer-uri="https://token.actions.githubusercontent.com"

# 3. The service account the pipeline will act as. This needs broad
#    project-edit-ish rights (it's provisioning IAM, secrets, Cloud Run,
#    Scheduler, Artifact Registry) — roles/editor is the quick path for a
#    demo project. For a real production setup, replace this with a
#    curated list of the specific roles main.tf's resources need instead
#    of the broad Editor role.
gcloud iam service-accounts create "gha-deployer" \
  --project="$PROJECT_ID" \
  --display-name="GitHub Actions deployer for compliance-agent"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/editor"

# Also needs to grant IAM roles to OTHER service accounts (the scanner SA,
# the scheduler invoker SA) as part of `terraform apply` — Editor alone
# doesn't cover that:
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/resourcemanager.projectIamAdmin"

# roles/editor deliberately excludes IAM policy-setting permissions on
# some services (Secret Manager, Cloud Run among them) — a real gap hit
# while deploying this, not a hypothetical. Without these, Terraform can
# create the secret and the Cloud Run Job but can't grant the scanner SA
# access to the secret, or let the scheduler SA invoke the job:
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin"

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/run.admin"

# And needs to read/write the state bucket from Step 0:
gcloud storage buckets add-iam-policy-binding "gs://${PROJECT_ID}-tfstate" \
  --member="serviceAccount:gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --role="roles/storage.objectAdmin"

# 4. Let the specific GitHub repo (via the pool/provider from step 1-2)
#    impersonate that service account
gcloud iam service-accounts add-iam-policy-binding \
  "gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com" \
  --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-pool/attribute.repository/${GITHUB_REPO}"

# 5. Print the two values the workflow needs
echo "WIF_PROVIDER: projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-pool/providers/github-provider"
echo "DEPLOY_SERVICE_ACCOUNT: gha-deployer@${PROJECT_ID}.iam.gserviceaccount.com"
```

## Wire it into GitHub

In the repo: **Settings → Secrets and variables → Actions**

**Variables** tab (not secret — these aren't sensitive on their own):
- `WIF_PROVIDER` → the `projects/.../workloadIdentityPools/...` string from step 5
- `DEPLOY_SERVICE_ACCOUNT` → the `gha-deployer@...` email from step 5

**Secrets** tab:
- `SLACK_WEBHOOK_URL` → your Slack incoming webhook URL (only needed once; the workflow passes it to Terraform as `TF_VAR_slack_webhook_url`)

## First run

Push a trivial change under `deploy/terraform/` (or use **Actions → Deploy
compliance-agent → Run workflow** for `workflow_dispatch`) and watch the
Actions tab. If `auth` fails, the error will point at either the
attribute-condition (repo name mismatch — check case) or a missing IAM
binding — re-check steps 3-4 above.

## After this is set up

Going forward, don't run `terraform apply` locally for this project again —
let the pipeline do it, so state, plan history, and who-changed-what all
live in one place (GitHub's Actions history) instead of split between your
laptop and CI. `terraform plan` locally is still fine any time you want to
check something without pushing.
