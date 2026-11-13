#!/usr/bin/env bash
#
# Bootstrap CI/CD access for one LiteLogin environment (one AWS account).
#
# Run once per account by an administrator, with that account's Identity
# Center profile. Safe to re-run: every step creates the resource if it's
# missing and otherwise brings it back to the expected configuration.
#
# Creates, in the AWS account:
#   - S3 bucket for Terraform/OpenTofu state (versioned, encrypted, private, TLS only)
#   - IAM OIDC provider for GitHub Actions (token.actions.githubusercontent.com)
#   - litelogin-deploy: assumed by GitHub Actions jobs that run in the
#     matching GitHub environment; AdministratorAccess
#   - litelogin-plan: assumed by pull request jobs; ReadOnlyAccess plus the
#     state lock files
#
# With --github, also configures the GitHub repository (requires `gh auth login`):
#   - a GitHub environment named after the LiteLogin environment, limited to
#     the main branch; prod also requires approval by the user running the script
#   - environment variables AWS_DEPLOY_ROLE_ARN, AWS_REGION, TF_STATE_BUCKET
#   - repository variables AWS_PLAN_ROLE_ARN_<ENV>, AWS_REGION_<ENV> and
#     TF_STATE_BUCKET_<ENV>, for pull request plans (which don't run in an
#     environment, so can't read environment variables)
#
# Usage:
#   AWS_PROFILE=litelogin-dev scripts/bootstrap-account.sh dev --region us-east-1 --github

set -euo pipefail

readonly GITHUB_OIDC_HOST="token.actions.githubusercontent.com"
readonly GITHUB_OIDC_URL="https://${GITHUB_OIDC_HOST}"
readonly GITHUB_OIDC_AUDIENCE="sts.amazonaws.com"
# AWS validates GitHub's OIDC certificates against its own trust store, so
# these thumbprints are not used for validation. Some API versions still
# require at least one.
readonly GITHUB_OIDC_THUMBPRINTS=(6938fd4d98bab03faadb97b34396831e3780aea1 1c58a3a8518e8759bf075b76b750d4f2df264fcd)

readonly DEPLOY_ROLE="litelogin-deploy"
readonly PLAN_ROLE="litelogin-plan"

REPO="litelogin/litelogin"
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-}}"
CONFIGURE_GITHUB=false
STATE_ONLY=false
ASSUME_YES=false
ENVIRONMENT=""

usage() {
  cat <<EOF
Usage: $(basename "$0") <environment> --region <region> [options]

Bootstraps CI/CD access for one LiteLogin environment in the AWS account of
the current AWS credentials (e.g. AWS_PROFILE=litelogin-dev). The
environment is a name such as dev, qa or prod: 2 to 16 lower case letters
and digits, starting with a letter.

Options:
  --region <region>   AWS region for the state bucket (default: \$AWS_REGION)
  --repo <owner/name> GitHub repository allowed to assume the roles (default: ${REPO})
  --github            Also create the GitHub environment and variables
  --state-only        Only create the state bucket and backend.hcl, with no
                      GitHub OIDC provider or roles (for deploying from your
                      own machine; see SelfHosting.md)
  --yes               Don't ask for confirmation
  -h, --help          Show this help
EOF
}

log() { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --region) REGION="${2:?--region needs a value}"; shift ;;
      --repo) REPO="${2:?--repo needs a value}"; shift ;;
      --github) CONFIGURE_GITHUB=true ;;
      --state-only) STATE_ONLY=true ;;
      --yes) ASSUME_YES=true ;;
      -h|--help) usage; exit 0 ;;
      -*) usage >&2; die "unknown argument: $1" ;;
      *)
        [[ -z "$ENVIRONMENT" ]] || die "more than one environment given: ${ENVIRONMENT} and $1"
        ENVIRONMENT="$1"
        ;;
    esac
    shift
  done

  [[ -n "$ENVIRONMENT" ]] || { usage >&2; die "an environment name (e.g. dev, qa or prod) is required"; }
  # The same rule as the environment variable of infra/modules/environment.
  [[ "$ENVIRONMENT" =~ ^[a-z][a-z0-9]{1,15}$ ]] ||
    die "environment must be 2 to 16 lower case letters and digits, starting with a letter: ${ENVIRONMENT}"
  [[ -n "$REGION" ]] || die "no region: pass --region or set AWS_REGION"
  [[ "$STATE_ONLY" != true || "$CONFIGURE_GITHUB" != true ]] || die "--github and --state-only don't go together"
  [[ "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repo must look like owner/name"

  command -v aws >/dev/null || die "the AWS CLI is required"
  command -v jq >/dev/null || die "jq is required"
  if [[ "$STATE_ONLY" != true ]]; then
    # gh is needed to read the repository's OIDC subject format, even without --github.
    command -v gh >/dev/null || die "the GitHub CLI (gh) is required; run gh auth login"
  fi
}

# resolve_sub_prefix sets SUB_PREFIX to the start of the `sub` claim in the
# repository's GitHub Actions OIDC tokens.
#
# Repositories that use immutable subjects identify the owner and repository
# by name and numeric ID (repo:owner@123/name@456), so a deleted and
# recreated repository can't assume the roles. Older repositories use
# repo:owner/name. GitHub reports which one applies.
resolve_sub_prefix() {
  local customization
  customization="$(gh api "repos/${REPO}/actions/oidc/customization/sub")" ||
    die "could not read the OIDC subject settings for ${REPO} (does gh have access to it?)"

  if [[ "$(jq -r '.use_default' <<<"$customization")" != "true" ]]; then
    die "${REPO} uses a custom OIDC subject template; this script only supports the default one"
  fi
  SUB_PREFIX="$(jq -r '.sub_claim_prefix // empty' <<<"$customization")"
  [[ -n "$SUB_PREFIX" ]] || SUB_PREFIX="repo:${REPO}"
}

confirm_account() {
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
  CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
  STATE_BUCKET="litelogin-tofu-state-${ACCOUNT_ID}"

  if [[ "$STATE_ONLY" == true ]]; then
    cat <<EOF

  Environment:   ${ENVIRONMENT}
  AWS account:   ${ACCOUNT_ID}
  Caller:        ${CALLER_ARN}
  Region:        ${REGION}
  State bucket:  ${STATE_BUCKET}
  State only:    no GitHub OIDC provider or roles

EOF
  else
    resolve_sub_prefix
    cat <<EOF

  Environment:   ${ENVIRONMENT}
  AWS account:   ${ACCOUNT_ID}
  Caller:        ${CALLER_ARN}
  Region:        ${REGION}
  State bucket:  ${STATE_BUCKET}
  GitHub repo:   ${REPO}
  OIDC subject:  ${SUB_PREFIX}:...
  Configure GitHub environment: ${CONFIGURE_GITHUB}

EOF
  fi
  if [[ "$ASSUME_YES" != true ]]; then
    read -r -p "Bootstrap this account for '${ENVIRONMENT}'? [y/N] " answer
    [[ "$answer" =~ ^[Yy]$ ]] || die "aborted"
  fi
}

ensure_state_bucket() {
  log "State bucket s3://${STATE_BUCKET}"
  if aws s3api head-bucket --bucket "$STATE_BUCKET" 2>/dev/null; then
    log "  exists"
  else
    if [[ "$REGION" == "us-east-1" ]]; then
      aws s3api create-bucket --bucket "$STATE_BUCKET" --region "$REGION" >/dev/null
    else
      aws s3api create-bucket --bucket "$STATE_BUCKET" --region "$REGION" \
        --create-bucket-configuration "LocationConstraint=${REGION}" >/dev/null
    fi
    aws s3api wait bucket-exists --bucket "$STATE_BUCKET"
    log "  created"
  fi

  aws s3api put-bucket-ownership-controls --bucket "$STATE_BUCKET" \
    --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
  aws s3api put-public-access-block --bucket "$STATE_BUCKET" \
    --public-access-block-configuration \
    'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
  aws s3api put-bucket-versioning --bucket "$STATE_BUCKET" \
    --versioning-configuration Status=Enabled
  aws s3api put-bucket-encryption --bucket "$STATE_BUCKET" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]}'
  aws s3api put-bucket-lifecycle-configuration --bucket "$STATE_BUCKET" >/dev/null \
    --lifecycle-configuration '{
      "Rules": [{
        "ID": "expire-old-state-versions",
        "Status": "Enabled",
        "Filter": {},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 90},
        "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
      }]
    }'
  aws s3api put-bucket-policy --bucket "$STATE_BUCKET" --policy "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::${STATE_BUCKET}", "arn:aws:s3:::${STATE_BUCKET}/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
EOF
)"
  log "  versioning, encryption, public access block, lifecycle and TLS-only policy applied"
}

ensure_oidc_provider() {
  OIDC_PROVIDER_ARN="arn:aws:iam::${ACCOUNT_ID}:oidc-provider/${GITHUB_OIDC_HOST}"
  log "GitHub OIDC provider"
  if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_PROVIDER_ARN" >/dev/null 2>&1; then
    log "  exists"
    local audiences
    audiences="$(aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$OIDC_PROVIDER_ARN" \
      --query 'ClientIDList' --output text)"
    if [[ " ${audiences} " != *" ${GITHUB_OIDC_AUDIENCE} "* ]]; then
      aws iam add-client-id-to-open-id-connect-provider \
        --open-id-connect-provider-arn "$OIDC_PROVIDER_ARN" --client-id "$GITHUB_OIDC_AUDIENCE"
      log "  added audience ${GITHUB_OIDC_AUDIENCE}"
    fi
  else
    aws iam create-open-id-connect-provider \
      --url "$GITHUB_OIDC_URL" \
      --client-id-list "$GITHUB_OIDC_AUDIENCE" \
      --thumbprint-list "${GITHUB_OIDC_THUMBPRINTS[@]}" >/dev/null
    log "  created"
  fi
}

# trust_policy <sub claim> prints a role trust policy for GitHub Actions jobs
# whose OIDC token has exactly that subject.
trust_policy() {
  cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "${OIDC_PROVIDER_ARN}"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "${GITHUB_OIDC_HOST}:aud": "${GITHUB_OIDC_AUDIENCE}",
        "${GITHUB_OIDC_HOST}:sub": "$1"
      }
    }
  }]
}
EOF
}

# ensure_role <name> <description> <trust policy JSON>
ensure_role() {
  local name="$1" description="$2" trust="$3"
  if aws iam get-role --role-name "$name" >/dev/null 2>&1; then
    aws iam update-assume-role-policy --role-name "$name" --policy-document "$trust"
    aws iam update-role --role-name "$name" --description "$description" --max-session-duration 3600
    log "  ${name}: exists, trust policy updated"
  else
    aws iam create-role --role-name "$name" --description "$description" \
      --assume-role-policy-document "$trust" --max-session-duration 3600 \
      --tags "Key=Project,Value=litelogin" "Key=Environment,Value=${ENVIRONMENT}" >/dev/null
    log "  ${name}: created"
  fi
}

ensure_roles() {
  log "IAM roles"

  # Deploy: only jobs running in the GitHub environment with this name. The
  # environment's protection rules (branch restriction, prod approval) decide
  # which jobs can run there.
  ensure_role "$DEPLOY_ROLE" \
    "GitHub Actions deploys for ${REPO} (${ENVIRONMENT} environment)" \
    "$(trust_policy "${SUB_PREFIX}:environment:${ENVIRONMENT}")"
  aws iam attach-role-policy --role-name "$DEPLOY_ROLE" \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  # Plan: pull request jobs. Read-only, except for the state lock files that
  # `tofu plan` writes and deletes.
  ensure_role "$PLAN_ROLE" \
    "GitHub Actions read-only plans for ${REPO} pull requests" \
    "$(trust_policy "${SUB_PREFIX}:pull_request")"
  aws iam attach-role-policy --role-name "$PLAN_ROLE" \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
  aws iam put-role-policy --role-name "$PLAN_ROLE" --policy-name state-locks --policy-document "$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "StateLockFiles",
    "Effect": "Allow",
    "Action": ["s3:PutObject", "s3:DeleteObject"],
    "Resource": "arn:aws:s3:::${STATE_BUCKET}/*.tflock"
  }]
}
EOF
)"
  log "  policies attached"

  DEPLOY_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${DEPLOY_ROLE}"
  PLAN_ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/${PLAN_ROLE}"
}

write_backend_config() {
  local env_dir
  env_dir="$(cd "$(dirname "$0")/.." && pwd)/infra/envs/${ENVIRONMENT}"
  local content
  content="bucket = \"${STATE_BUCKET}\"
key    = \"litelogin/${ENVIRONMENT}/terraform.tfstate\"
region = \"${REGION}\""

  if [[ -d "$env_dir" ]]; then
    printf '%s\n' "$content" > "${env_dir}/backend.hcl"
    log "Wrote ${env_dir#"$(pwd)/"}/backend.hcl (git-ignored)"
  else
    log "infra/envs/${ENVIRONMENT} doesn't exist yet. Its backend.hcl will be:"
    printf '%s\n' "$content" | sed 's/^/    /'
  fi
}

configure_github() {
  [[ "$CONFIGURE_GITHUB" == true ]] || return 0
  log "GitHub environment '${ENVIRONMENT}' in ${REPO}"

  local env_body
  if [[ "$ENVIRONMENT" == "prod" ]]; then
    local reviewer_id
    reviewer_id="$(gh api user --jq .id)"
    env_body="{\"reviewers\":[{\"type\":\"User\",\"id\":${reviewer_id}}],\"deployment_branch_policy\":{\"protected_branches\":false,\"custom_branch_policies\":true}}"
  else
    env_body='{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
  fi

  if ! printf '%s' "$env_body" | gh api -X PUT "repos/${REPO}/environments/${ENVIRONMENT}" --input - >/dev/null; then
    warn "could not create the environment with protection rules."
    warn "Required reviewers on private repositories need a paid GitHub plan."
    warn "Creating it without rules; add protection manually in Settings > Environments."
    gh api -X PUT "repos/${REPO}/environments/${ENVIRONMENT}" >/dev/null
  else
    # Only the main branch may deploy. Creating a policy that already exists
    # fails, which is fine.
    gh api -X POST "repos/${REPO}/environments/${ENVIRONMENT}/deployment-branch-policies" \
      -f name=main -f type=branch >/dev/null 2>&1 || true
    if [[ "$ENVIRONMENT" == "prod" ]]; then
      log "  created: main branch only, approval required"
    else
      log "  created: main branch only"
    fi
  fi

  gh variable set AWS_DEPLOY_ROLE_ARN --repo "$REPO" --env "$ENVIRONMENT" --body "$DEPLOY_ROLE_ARN"
  gh variable set AWS_REGION --repo "$REPO" --env "$ENVIRONMENT" --body "$REGION"
  gh variable set TF_STATE_BUCKET --repo "$REPO" --env "$ENVIRONMENT" --body "$STATE_BUCKET"

  local upper_env
  upper_env="$(printf '%s' "$ENVIRONMENT" | tr '[:lower:]' '[:upper:]')"
  gh variable set "AWS_PLAN_ROLE_ARN_${upper_env}" --repo "$REPO" --body "$PLAN_ROLE_ARN"
  gh variable set "AWS_REGION_${upper_env}" --repo "$REPO" --body "$REGION"
  gh variable set "TF_STATE_BUCKET_${upper_env}" --repo "$REPO" --body "$STATE_BUCKET"
  log "  variables set"
}

main() {
  parse_args "$@"
  confirm_account
  ensure_state_bucket
  write_backend_config
  if [[ "$STATE_ONLY" == true ]]; then
    printf '\nDone. %s (account %s): state bucket %s\n' "$ENVIRONMENT" "$ACCOUNT_ID" "$STATE_BUCKET"
    [[ -d "$(dirname "$0")/../infra/envs/${ENVIRONMENT}" ]] ||
      printf 'Next: create infra/envs/%s from infra/envs/example (SelfHosting.md).\n' "$ENVIRONMENT"
    return
  fi
  ensure_oidc_provider
  ensure_roles
  configure_github

  cat <<EOF

Done. ${ENVIRONMENT} (account ${ACCOUNT_ID}):
  State bucket:  ${STATE_BUCKET}
  Deploy role:   ${DEPLOY_ROLE_ARN}   (GitHub environment '${ENVIRONMENT}')
  Plan role:     ${PLAN_ROLE_ARN}   (pull requests)

In a workflow job:
  environment: ${ENVIRONMENT}
  permissions:
    id-token: write
    contents: read
  steps:
    - uses: aws-actions/configure-aws-credentials@v6
      with:
        role-to-assume: \${{ vars.AWS_DEPLOY_ROLE_ARN }}
        aws-region: \${{ vars.AWS_REGION }}
EOF
}

main "$@"
