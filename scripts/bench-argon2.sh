#!/usr/bin/env bash
#
# Benchmark argon2id password verification on Lambda at several memory
# sizes, to choose the Auth Lambda's memory setting.
#
# Creates a temporary IAM role and function (litelogin-argon2bench), runs
# the benchmark, prints a table, and deletes both, even if it fails.
#
# Usage:
#   AWS_PROFILE=litelogin-dev scripts/bench-argon2.sh [memory_mb ...]
#   (default: 512 1024 1769 3008)

set -euo pipefail

readonly NAME="litelogin-argon2bench"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
readonly ROOT
MEMORY_SIZES=("${@:-512 1024 1769 3008}")
read -r -a MEMORY_SIZES <<<"${MEMORY_SIZES[*]}"

WORK="$(mktemp -d)"
cleanup() {
  aws lambda delete-function --function-name "$NAME" >/dev/null 2>&1 || true
  aws iam detach-role-policy --role-name "$NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole >/dev/null 2>&1 || true
  aws iam delete-role --role-name "$NAME" >/dev/null 2>&1 || true
  aws logs delete-log-group --log-group-name "/aws/lambda/${NAME}" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> Building"
(cd "$ROOT" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -tags lambda.norpc -trimpath \
  -ldflags="-s -w" -o "$WORK/bootstrap" ./cmd/argon2bench)
(cd "$WORK" && zip -q bench.zip bootstrap)

echo "==> Creating temporary role and function"
role_arn="$(aws iam create-role --role-name "$NAME" --query Role.Arn --output text \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}')"
aws iam attach-role-policy --role-name "$NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
# A new role takes a few seconds before Lambda can assume it.
for attempt in $(seq 1 12); do
  if aws lambda create-function --function-name "$NAME" --runtime provided.al2023 --architectures arm64 \
    --handler bootstrap --role "$role_arn" --zip-file "fileb://$WORK/bench.zip" \
    --memory-size "${MEMORY_SIZES[0]}" --timeout 120 >/dev/null 2>"$WORK/err"; then
    break
  fi
  [[ $attempt -lt 12 ]] || { cat "$WORK/err" >&2; exit 1; }
  sleep 5
done
aws lambda wait function-active-v2 --function-name "$NAME"

invoke() { # payload
  aws lambda invoke --function-name "$NAME" --cli-binary-format raw-in-base64-out \
    --payload "$1" "$WORK/out.json" >/dev/null
  cat "$WORK/out.json"
}

printf '\n%-10s %-5s %-12s %8s %8s %8s\n' "memory_mb" "cpus" "concurrency" "p50_ms" "p90_ms" "max_ms"
for mem in "${MEMORY_SIZES[@]}"; do
  aws lambda update-function-configuration --function-name "$NAME" --memory-size "$mem" >/dev/null
  aws lambda wait function-updated-v2 --function-name "$NAME"
  for conc in 1 4; do
    out="$(invoke "{\"iterations\":20,\"concurrency\":${conc}}")"
    python3 -c '
import json, sys
r = json.loads(sys.argv[1])
if "errorMessage" in r: sys.exit("benchmark failed: " + r["errorMessage"])
print("%-10s %-5s %-12s %8.1f %8.1f %8.1f" % (r["memory_mb"], r["cpus"], r["concurrency"], r["p50_ms"], r["p90_ms"], r["max_ms"]))
' "$out"
  done
done
echo
echo "Parameters: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["params"])' "$WORK/out.json")"
echo "Target: p50 of 50-150 ms for one verification (Architecture.md)."
