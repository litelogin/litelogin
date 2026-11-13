#!/usr/bin/env bash
#
# Deploy a LiteLogin environment from this machine, from an empty AWS
# account to a working issuer (SelfHosting.md, "Quick deploy").
#
# Each run works out where the deployment is from its actual state (the
# state bucket, the DNS zone and its delegation, pending changes) and
# continues from there, so after any stop, fix what it says and run it
# again. It never applies anything without showing the plan first:
#
#   - In a terminal, it asks before using the AWS account and before each
#     apply, and waits for the DNS delegation.
#   - Without one (in CI, or run by a tool), it stops at each of those
#     points with exit status 3 and says how to continue: confirm the
#     account with --account, apply a reviewed plan with --apply-plan, or
#     run it again once DNS is delegated.
#
# Usage:
#   AWS_PROFILE=litelogin-prod scripts/deploy.sh prod --domain login.example.com
#   AWS_PROFILE=litelogin-prod scripts/deploy.sh prod      # continue, or upgrade

set -euo pipefail

readonly REGION="us-east-1" # LiteLogin deploys to us-east-1 only (CloudFront and WAF).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly ROOT
readonly EXIT_NEEDS_INPUT=3

ENVIRONMENT=""
DOMAIN=""
SETUP="lean"
SETUP_GIVEN=false
ALARM_EMAIL=""
ACCOUNT=""
APPLY_PLAN=""
SKIP_BUILD=false
DNS_WAIT_MINUTES=30
TF="${TF:-}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <environment> [options]

Deploys (or upgrades) the LiteLogin environment in infra/envs/<environment>
to the AWS account of the current credentials. Set AWS_PROFILE to that
account's profile. Run it again after any stop: it continues where it left off.

New environment (infra/envs/<environment> doesn't exist yet):
  --domain <domain>       Parent domain of the default login hosts, e.g.
                          login.example.com (required)
  --setup lean|full       Default: lean, for small deployments; full adds
                          custom login hosts, the full WAF, tracing and the
                          dashboard (Cost.md, "Setups")
  --alarm-email <address> Where alarms go (optional)

Options:
  --account <id>          The AWS account you expect: deploy without asking
                          if the credentials are for it, stop if they aren't
  --apply-plan <file>     Apply a plan this script saved and you reviewed,
                          then continue
  --skip-build            Use the packages already in dist/
  --dns-wait <minutes>    How long to wait for the DNS delegation in a
                          terminal (default: ${DNS_WAIT_MINUTES})
  -h, --help              Show this help

Exit status: 0 deployed and healthy; 1 an error or a failed health check;
3 stopped for your input (the message says what to do).
EOF
}

log() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

interactive() { [[ -t 0 && -t 1 ]]; }

# stop <message...> ends the run, waiting for the user: printed, exit 3.
stop() {
  printf '\n' >&2
  printf '%s\n' "$@" >&2
  exit "$EXIT_NEEDS_INPUT"
}

# ask <question>: yes or no, in a terminal.
ask() {
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" =~ ^[Yy]([Ee][Ss])?$ ]]
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN="${2:?--domain needs a value}"; shift ;;
      --setup) SETUP="${2:?--setup needs a value}"; SETUP_GIVEN=true; shift ;;
      --alarm-email) ALARM_EMAIL="${2:?--alarm-email needs a value}"; shift ;;
      --account) ACCOUNT="${2:?--account needs a value}"; shift ;;
      --apply-plan) APPLY_PLAN="${2:?--apply-plan needs a file}"; shift ;;
      --skip-build) SKIP_BUILD=true ;;
      --dns-wait) DNS_WAIT_MINUTES="${2:?--dns-wait needs minutes}"; shift ;;
      -h|--help) usage; exit 0 ;;
      -*) usage >&2; die "unknown argument: $1" ;;
      *)
        [[ -z "$ENVIRONMENT" ]] || die "more than one environment given: ${ENVIRONMENT} and $1"
        ENVIRONMENT="$1"
        ;;
    esac
    shift
  done

  [[ -n "$ENVIRONMENT" ]] || { usage >&2; die "an environment name (e.g. prod) is required"; }
  [[ "$ENVIRONMENT" =~ ^[a-z][a-z0-9]{1,15}$ ]] ||
    die "environment must be 2 to 16 lower case letters and digits, starting with a letter: ${ENVIRONMENT}"
  [[ "$ENVIRONMENT" != example ]] || die "infra/envs/example is the template; pick another name"
  [[ "$SETUP" == lean || "$SETUP" == full ]] || die "--setup must be lean or full"
  [[ "$DNS_WAIT_MINUTES" =~ ^[0-9]+$ ]] || die "--dns-wait must be a number of minutes"
  [[ -z "$ACCOUNT" || "$ACCOUNT" =~ ^[0-9]{12}$ ]] || die "--account must be a 12-digit AWS account ID"

  ENV_DIR="${ROOT}/infra/envs/${ENVIRONMENT}"
  PLAN_FILE="${ENV_DIR}/deploy.tfplan"
  CLI="${ROOT}/dist/litelogin"
}

check_tools() {
  local missing=()
  for tool in aws jq dig make go; do
    command -v "$tool" >/dev/null || missing+=("$tool")
  done
  if [[ -z "$TF" ]]; then
    if command -v tofu >/dev/null; then TF=tofu
    elif command -v terraform >/dev/null; then TF=terraform
    else missing+=("tofu or terraform")
    fi
  fi
  [[ ${#missing[@]} -eq 0 ]] || die "missing tools: ${missing[*]} (SelfHosting.md, \"Before you start\")"
}

# The credentials must be chosen on purpose: never whatever the default
# profile happens to be.
check_credentials() {
  if [[ -z "${AWS_PROFILE:-}" && -z "${AWS_ACCESS_KEY_ID:-}" ]]; then
    die "set AWS_PROFILE to the profile of ${ENVIRONMENT}'s AWS account (this script doesn't use the default profile)"
  fi
  local identity
  identity="$(aws sts get-caller-identity --output json 2>&1)" ||
    die "AWS credentials ${AWS_PROFILE:+(profile ${AWS_PROFILE}) }don't work: ${identity}
    For IAM Identity Center: aws sso login${AWS_PROFILE:+ --profile ${AWS_PROFILE}}"
  ACCOUNT_ID="$(jq -r .Account <<<"$identity")"
  CALLER_ARN="$(jq -r .Arn <<<"$identity")"
}

# tfvar <name> reads a quoted value from the environment's terraform.tfvars,
# or else the variable's default in its main.tf.
tfvar() {
  local file="${ENV_DIR}/terraform.tfvars" value=""
  if [[ -f "$file" ]]; then
    value="$(sed -nE "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | tail -1)"
  fi
  if [[ -z "$value" && -f "${ENV_DIR}/main.tf" ]]; then
    value="$(awk -v name="$1" '
      $0 ~ "^variable \"" name "\"" { inside = 1 }
      inside && /^}/ { inside = 0 }
      inside && match($0, /default *= *"[^"]*"/) {
        v = substr($0, RSTART, RLENGTH); sub(/^default *= *"/, "", v); sub(/"$/, "", v); print v; exit
      }' "${ENV_DIR}/main.tf")"
  fi
  printf '%s' "$value"
}

confirm_target() {
  local new=false
  if [[ ! -d "$ENV_DIR" ]]; then
    new=true
    [[ -n "$DOMAIN" ]] || die "infra/envs/${ENVIRONMENT} doesn't exist yet: pass --domain (e.g. --domain login.example.com) to create it"
    [[ "$DOMAIN" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]] || die "--domain doesn't look like a domain: ${DOMAIN}"
  else
    if [[ -n "$DOMAIN" || "$SETUP_GIVEN" == true || -n "$ALARM_EMAIL" ]]; then
      warn "infra/envs/${ENVIRONMENT} exists: --domain, --setup and --alarm-email are ignored; edit its terraform.tfvars instead"
    fi
    DOMAIN="$(tfvar default_host_domain)"
    SETUP="$(tfvar setup)"
    [[ -n "$SETUP" ]] || SETUP="(the root's default)"
  fi

  cat <<EOF

  Environment:  ${ENVIRONMENT}$([[ "$new" == true ]] && echo "   (new: infra/envs/${ENVIRONMENT} will be created)")
  AWS account:  ${ACCOUNT_ID}
  Caller:       ${CALLER_ARN}${AWS_PROFILE:+   (profile ${AWS_PROFILE})}
  Region:       ${REGION}
  Login hosts:  *.${DOMAIN:-?}
  Setup:        ${SETUP}
  Tool:         ${TF}
EOF

  if [[ -n "$ACCOUNT" ]]; then
    [[ "$ACCOUNT" == "$ACCOUNT_ID" ]] ||
      die "these credentials are for account ${ACCOUNT_ID}, not ${ACCOUNT} (--account): check AWS_PROFILE"
  elif interactive; then
    ask "Deploy ${ENVIRONMENT} to account ${ACCOUNT_ID}?" || stop "Stopped: nothing was changed."
  else
    stop "Stopped before using account ${ACCOUNT_ID}." \
      "If it's the right account for ${ENVIRONMENT}, run again with --account ${ACCOUNT_ID}."
  fi

  if [[ "$new" == true ]]; then
    create_env_dir
  fi
}

create_env_dir() {
  log "Creating infra/envs/${ENVIRONMENT} from infra/envs/example"
  mkdir -p "$ENV_DIR"
  cp "${ROOT}/infra/envs/example/main.tf" "${ROOT}/infra/envs/example/.terraform.lock.hcl" \
    "${ROOT}/infra/envs/example/backend.hcl.example" "$ENV_DIR/"
  {
    printf '# Written by scripts/deploy.sh (git-ignored). Edit and run it again.\n'
    printf 'environment         = "%s"\n' "$ENVIRONMENT"
    printf 'default_host_domain = "%s"\n' "$DOMAIN"
    printf 'setup               = "%s"\n' "$SETUP"
    [[ -z "$ALARM_EMAIL" ]] || printf 'alarm_email         = "%s"\n' "$ALARM_EMAIL"
  } > "${ENV_DIR}/terraform.tfvars"
  info "terraform.tfvars: environment, default_host_domain = ${DOMAIN}, setup = ${SETUP}"
}

ensure_state() {
  if [[ -f "${ENV_DIR}/backend.hcl" ]]; then
    return
  fi
  log "State bucket (scripts/bootstrap-account.sh --state-only)"
  "${ROOT}/scripts/bootstrap-account.sh" "$ENVIRONMENT" --region "$REGION" --state-only --yes |
    sed 's/^/    /'
  [[ -f "${ENV_DIR}/backend.hcl" ]] || die "bootstrap didn't write ${ENV_DIR}/backend.hcl"
}

build() {
  if [[ "$SKIP_BUILD" == true || -n "$APPLY_PLAN" ]]; then
    # A saved plan applies the packages it was made with: rebuilding them
    # could change what it uploads.
    for f in auth admin worker rotate; do
      [[ -f "${ROOT}/dist/${f}.zip" ]] || die "dist/${f}.zip is missing: run without --skip-build"
    done
    [[ -x "$CLI" ]] || die "dist/litelogin is missing: run make cli"
    return
  fi
  log "Building the Lambda packages and the CLI (make package cli)"
  make -C "$ROOT" package cli >/dev/null
  info "dist/: auth.zip, admin.zip, worker.zip, rotate.zip, litelogin"
}

tf() { (cd "$ENV_DIR" && "$TF" "$@"); }

# color: -no-color unless in a terminal, so logs and tools read plain text.
color() { interactive || printf '%s' -no-color; }

init() {
  log "Initializing ${TF} in infra/envs/${ENVIRONMENT}"
  tf init -input=false -backend-config=backend.hcl >/dev/null
}

# plan_and_apply <description> [plan options...] plans, shows the plan and
# applies it once confirmed. Returns 0 when there was nothing to do or it
# applied.
plan_and_apply() {
  local what="$1"
  shift
  log "Planning ${what}"
  rm -f "$PLAN_FILE"
  # Only the changes: not the refresh lines before them, nor the footer
  # that says to run "terraform apply" (this script applies the plan) or
  # warns about -target (the zone goes first on purpose).
  # shellcheck disable=SC2046 # color prints one flag or nothing
  tf plan -input=false $(color) -out="$PLAN_FILE" "$@" | awk '
    /(Terraform|OpenTofu) will perform/ { show = 1 }
    /Warning: Resource targeting is in effect/ || /^Saved the plan to:/ { exit }
    show && !/^─+$/ { print }'
  local summary
  summary="$(tf show -json "$PLAN_FILE" | jq -r '
    [.resource_changes[]? | .change.actions] as $a
    | {create: ([$a[] | select(. == ["create"])] | length),
       update: ([$a[] | select(. == ["update"])] | length),
       replace: ([$a[] | select(length == 2)] | length),
       delete: ([$a[] | select(. == ["delete"])] | length)}
    | "\(.create) \(.update) \(.replace) \(.delete)"')"
  local create update replace delete
  read -r create update replace delete <<<"$summary"
  if [[ $((create + update + replace + delete)) -eq 0 ]]; then
    rm -f "$PLAN_FILE"
    info "No changes."
    return 0
  fi
  info "Plan: ${create} to create, ${update} to update, ${replace} to replace, ${delete} to destroy."
  # Every code change replaces each function's package upload and signing
  # job; anything else replaced or destroyed deserves a look.
  local packages others
  packages="$(tf show -json "$PLAN_FILE" | jq -r '[.resource_changes[]? | select((.change.actions | length) == 2)
    | select(.address | test("\\.(aws_s3_object|aws_signer_signing_job)\\.package\\[0\\]$"))] | length')"
  others="$(tf show -json "$PLAN_FILE" | jq -r '.resource_changes[]? | select(.change.actions | index("delete"))
    | select(((.address | test("\\.(aws_s3_object|aws_signer_signing_job)\\.package\\[0\\]$")) and (.change.actions | length) == 2) | not)
    | "    \(.change.actions | if length == 2 then "replace" else "destroy" end)  \(.address)"')"
  [[ "$packages" -eq 0 ]] || info "(${packages} of the replacements are new Lambda packages and their signing jobs, as after any code change.)"
  if [[ -n "$others" ]]; then
    warn "this plan replaces or destroys:"
    printf '%s\n' "$others" >&2
  fi
  if interactive; then
    ask "Apply this plan?" || stop "Stopped: the plan wasn't applied (saved in ${PLAN_FILE#"${ROOT}/"})."
    apply_plan "$PLAN_FILE"
  else
    stop "Stopped: review the plan above (or: cd infra/envs/${ENVIRONMENT} && ${TF} show deploy.tfplan)." \
      "To apply exactly that plan, run: scripts/deploy.sh ${ENVIRONMENT} --account ${ACCOUNT_ID} --apply-plan ${PLAN_FILE#"${ROOT}/"}"
  fi
}

apply_plan() {
  local plan="$1"
  [[ "$plan" == /* ]] || plan="${ROOT}/${plan}"
  [[ -f "$plan" ]] || die "no plan file ${plan}"
  log "Applying ${plan#"${ROOT}/"}"
  # shellcheck disable=SC2046
  tf apply -input=false $(color) "$plan"
  rm -f "$plan"
  if ! all_applied; then
    info "(Only the DNS zone so far: Terraform's warning about -target is expected. The rest comes next.)"
  fi
}

# all_applied: the state has more than the DNS zone (the first, targeted
# apply).
all_applied() {
  local resources
  resources="$(tf state list 2>/dev/null || true)"
  grep -q 'module.litelogin.module.edge' <<<"$resources"
}

zone_exists() {
  # Not piped into grep -q: with pipefail, grep stopping at the first match
  # would fail the pipeline.
  local resources
  resources="$(tf state list 2>/dev/null || true)"
  grep -qx 'module.litelogin.module.dns.aws_route53_zone.this' <<<"$resources"
}

# delegation <server> prints the NS records the parent domain's name
# server gives for DOMAIN. It asks the parent directly, not a resolver,
# which can cache an old delegation (say, to an earlier zone of the same
# name) for hours.
delegation() {
  # A referral is in the authority section; the parent's own records, if
  # it serves DOMAIN itself, in the answer section.
  dig +norec +noall +authority +answer NS "$DOMAIN" @"$1" 2>/dev/null |
    awk '$4 == "NS" { print tolower($5) }' | sed 's/\.$//' | sort -u
}

# delegated: every name server of the parent domain delegates DOMAIN only to
# the zone's name servers (all four, or some of them: that resolves too).
# Every server, three times each: a DNS provider updates its servers one by
# one, and each name can be many anycast machines that don't all have the
# change yet.
delegated() {
  local want parent_servers server got round
  want="$(tf output -json dns_name_servers | jq -r '.[]' | tr '[:upper:]' '[:lower:]' | sed 's/\.$//' | sort -u)"
  parent_servers="$(dig +short NS "${DOMAIN#*.}" 2>/dev/null)"
  [[ -n "$parent_servers" ]] || return 1
  for round in 1 2 3; do
    for server in $parent_servers; do
      got="$(delegation "$server")"
      [[ -n "$got" ]] || return 1
      # comm -23: records at the parent that aren't the zone's.
      [[ -z "$(comm -23 <(printf '%s\n' "$got") <(printf '%s\n' "$want"))" ]] || return 1
    done
    [[ $round -eq 3 ]] || sleep 1
  done
}

ensure_dns() {
  if ! zone_exists; then
    plan_and_apply "the DNS zone for ${DOMAIN} (first, so the certificate can validate)" \
      -target=module.litelogin.module.dns
  fi
  if delegated; then
    info "${DOMAIN} is delegated to its Route 53 zone."
    return
  fi
  log "Delegate ${DOMAIN} to Route 53"
  info "At the DNS provider of ${DOMAIN#*.}, add these NS records for ${DOMAIN}:"
  printf '\n'
  tf output -json dns_name_servers | jq -r --arg d "$DOMAIN" '.[] | "      \($d).  NS  \(.)."'
  printf '\n'
  if ! interactive || [[ "$DNS_WAIT_MINUTES" -eq 0 ]]; then
    stop "Stopped: waiting for the NS records above at ${DOMAIN#*.}'s DNS provider. Once they're added, run:" \
      "  scripts/deploy.sh ${ENVIRONMENT} --account ${ACCOUNT_ID}"
  fi
  info "Waiting up to ${DNS_WAIT_MINUTES} minutes for public DNS to show them (Ctrl-C to stop; run again later to continue)..."
  local deadline=$((SECONDS + DNS_WAIT_MINUTES * 60))
  until delegated; do
    [[ $SECONDS -lt $deadline ]] ||
      stop "Stopped: ${DOMAIN} isn't delegated yet. Check the records, then run this again."
    sleep 15
  done
  info "${DOMAIN} is delegated."
}

ensure_signing_key() {
  log "Signing key"
  local fn out
  fn="$(tf output -raw rotate_function_name)"
  out="$(mktemp)"
  aws lambda invoke --region "$REGION" --function-name "$fn" \
    --cli-binary-format raw-in-base64-out --payload '{}' "$out" >/dev/null
  local active
  active="$(jq -r '.active // empty' "$out" 2>/dev/null || true)"
  if [[ -z "$active" ]]; then
    cat "$out" >&2
    rm -f "$out"
    die "the rotate function returned no active key; see its log (/aws/lambda/${fn})"
  fi
  rm -f "$out"
  info "active key ${active}"
}

configure_cli() {
  [[ -n "${AWS_PROFILE:-}" ]] || return 0
  log "CLI"
  "$CLI" configure --environment "$ENVIRONMENT" | sed 's/^/    /'
}

check_health() {
  log "Status (dist/litelogin status)"
  "$CLI" status --environment "$ENVIRONMENT"
}

next_steps() {
  local profile="${AWS_PROFILE:+--profile ${AWS_PROFILE} }"
  cat <<EOF

Deployed. Create an org with its login host and a client:

  dist/litelogin ${profile}init --org "Acme" --client "Acme Portal" \\
    --redirect-uri https://app.acme.com/callback

It prints the issuer (https://acme.${DOMAIN}), the client ID and, once, the
client secret. To try a sign-in end to end: dist/litelogin client test CLIENT
(SelfHosting.md, "Operators and the CLI").
EOF
}

main() {
  parse_args "$@"
  check_tools
  check_credentials
  confirm_target
  ensure_state
  build
  init
  if [[ -n "$APPLY_PLAN" ]]; then
    apply_plan "$APPLY_PLAN"
  fi
  ensure_dns
  plan_and_apply "${ENVIRONMENT}"
  ensure_signing_key
  configure_cli
  if check_health; then
    next_steps
  else
    die "the deployment isn't healthy: see the checks above"
  fi
}

main "$@"
