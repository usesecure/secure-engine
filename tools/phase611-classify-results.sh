#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 RESULTS_JSON" >&2
  exit 64
fi

results=$1
if [[ ! -f $results ]]; then
  echo "results file not found: $results" >&2
  exit 66
fi

jq -e '
  [.lanes[] | select(.lane == "native" and .scanner == "secure-engine" and .state == "completed")]
  | length == 1
' "$results" >/dev/null

error_count=$(
  jq -r '
    [.lanes[]
      | select(.lane == "native" and .scanner == "secure-engine" and .state == "completed")
      | .cases[]
      | select(.outcome == "fn" or .outcome == "fp")]
    | length
  ' "$results"
)
if [[ $error_count -ne 41 ]]; then
  echo "expected 41 Secure Engine native errors, found $error_count" >&2
  exit 65
fi

printf 'outcome\tfamily\tframework\tsource_format\ttopology\texpected\tpair_id\n'
jq -r '
  .lanes[]
  | select(.lane == "native" and .scanner == "secure-engine" and .state == "completed")
  | .cases
  | map(select(.outcome == "fn" or .outcome == "fp"))
  | sort_by(.outcome, .pair_id)
  | .[]
  | [.outcome, .family, .framework, .source_format, .topology, .expected, .pair_id]
  | @tsv
' "$results"
