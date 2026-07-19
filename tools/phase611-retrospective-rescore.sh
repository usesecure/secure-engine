#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: $0 SECURE_BINARY SECURE_BENCH_ROOT OUTPUT_DIRECTORY [--resume-preserved]" >&2
  exit 64
fi

engine=$(realpath "$1")
bench=$(realpath "$2")
output=$3
resume=false
if [[ ${4:-} == --resume-preserved ]]; then
  resume=true
elif [[ $# -eq 4 ]]; then
  echo "unknown option: $4" >&2
  exit 64
fi
expected_bench_commit=df1cf5f078ec861581f1d11dcc8d4ae35feb0315
expected_historical_hash=6266b1c1b064cd15f9f812d66d638eb2edcf0ccac2fbf9162d79134902034185
manifest=$bench/phase19/holdout/manifest.json
historical=$bench/phase20/output/results.json

if [[ ! -x $engine ]]; then
  echo "Secure Engine binary is not executable: $engine" >&2
  exit 66
fi
if [[ ! -f $manifest || ! -f $historical ]]; then
  echo "required read-only development inputs are missing" >&2
  exit 66
fi
if [[ $(git -C "$bench" rev-parse HEAD) != "$expected_bench_commit" ]]; then
  echo "Secure Bench commit drift" >&2
  exit 65
fi
if [[ -n $(git -C "$bench" status --short) ]]; then
  echo "Secure Bench working tree is not clean" >&2
  exit 65
fi
if [[ $(sha256sum "$historical" | cut -d' ' -f1) != "$expected_historical_hash" ]]; then
  echo "historical result hash drift" >&2
  exit 65
fi
if [[ -e $output && $resume == false ]]; then
  echo "output directory must be fresh: $output" >&2
  exit 73
fi
if [[ -e $output && $resume == true ]]; then
  if [[ -e $output/observations.jsonl ]] || [[ $(find "$output/raw" -type f -name '*.json' | wc -l) -ne 1 ]]; then
    echo "resume requires exactly one preserved raw report and no observations" >&2
    exit 73
  fi
fi
if [[ $output == "$bench" || $output == "$bench"/* ]]; then
  echo "output directory must be outside Secure Bench" >&2
  exit 73
fi
if ps -eo comm= | awk '$1 == "opengrep" || $1 == "semgrep" || $1 == "joern" || $1 == "ollama" { found=1 } END { exit !found }'; then
  echo "a prohibited scanner or AI process is active" >&2
  exit 75
fi

mkdir -p "$output/raw"
output=$(realpath "$output")
observations=$output/observations.jsonl

jq -r '
  .pairs[]
  | . as $pair
  | [$pair.first, $pair.second][]
  | [
      .case_id,
      .classification,
      .fixture_path,
      $pair.pair_id,
      $pair.assignment.family,
      $pair.assignment.framework,
      $pair.assignment.source_format,
      $pair.assignment.topology
    ]
  | @tsv
' "$manifest" |
while IFS=$'\t' read -r case_id expected fixture_path pair_id family framework source_format topology; do
  fixture=$bench/$fixture_path
  report=$output/raw/$case_id.json
  if [[ -s $report && $resume == true ]]; then
    exit_code=1
  else
    set +e
    bwrap \
      --die-with-parent \
      --unshare-net \
      --ro-bind / / \
      --bind "$output" "$output" \
      --proc /proc \
      --dev /dev \
      --chdir "$fixture" \
      "$engine" scan . \
        --format secure-json-v1 \
        --no-cache \
        --quiet \
        --output "$report"
    exit_code=$?
    set -e
  fi
  if [[ ! -s $report ]]; then
    echo "Secure Engine produced no report for $case_id (exit $exit_code)" >&2
    exit 70
  fi
  jq -e '
    .schema_version == "secure-json-v1"
    and .scan.complete
    and (.errors | length == 0)
    and (.analysis.truncated | not)
    and (.configuration.parse_cache_enabled | not)
    and (.configuration.suppressions | length == 0)
    and (.suppression_diagnostics | length == 0)
  ' "$report" >/dev/null
  finding_count=$(jq '.findings | length' "$report")
  if [[ $exit_code -ne 0 && $finding_count -eq 0 ]]; then
    echo "Secure Engine returned exit $exit_code without findings for $case_id" >&2
    exit 70
  fi
  if [[ $finding_count -gt 0 ]]; then
    predicted=true
  else
    predicted=false
  fi
  if [[ $expected == vulnerable && $predicted == true ]]; then
    outcome=tp
  elif [[ $expected == vulnerable ]]; then
    outcome=fn
  elif [[ $predicted == true ]]; then
    outcome=fp
  else
    outcome=tn
  fi
  report_sha256=$(sha256sum "$report" | cut -d' ' -f1)
  report_fingerprint=$(jq -r '.report_fingerprint' "$report")
  jq -cn \
    --arg case_id "$case_id" \
    --arg pair_id "$pair_id" \
    --arg expected "$expected" \
    --arg outcome "$outcome" \
    --arg family "$family" \
    --arg framework "$framework" \
    --arg source_format "$source_format" \
    --arg topology "$topology" \
    --arg report_sha256 "$report_sha256" \
    --arg report_fingerprint "$report_fingerprint" \
    --argjson finding_count "$finding_count" \
    --argjson predicted_positive "$predicted" \
    --argjson exit_code "$exit_code" \
    '{
      case_id: $case_id,
      pair_id: $pair_id,
      expected: $expected,
      finding_count: $finding_count,
      predicted_positive: $predicted_positive,
      outcome: $outcome,
      family: $family,
      framework: $framework,
      source_format: $source_format,
      topology: $topology,
      report_sha256: $report_sha256,
      report_fingerprint: $report_fingerprint,
      exit_code: $exit_code
    }' >>"$observations"
done

if [[ $(wc -l <"$observations") -ne 112 ]]; then
  echo "retrospective run did not produce exactly 112 observations" >&2
  exit 70
fi

jq '[
  .lanes[]
  | select(.lane == "native" and .scanner == "secure-engine" and .state == "completed")
  | .cases[]
]' "$historical" >"$output/historical-cases.json"

jq -s --slurpfile historical "$output/historical-cases.json" '
  def metrics:
    . as $rows
    | {
        tp: ([$rows[] | select(.outcome == "tp")] | length),
        fp: ([$rows[] | select(.outcome == "fp")] | length),
        tn: ([$rows[] | select(.outcome == "tn")] | length),
        fn: ([$rows[] | select(.outcome == "fn")] | length)
      } as $counts
    | $counts + {
        precision: {
          numerator: $counts.tp,
          denominator: ($counts.tp + $counts.fp),
          decimal: (if ($counts.tp + $counts.fp) == 0 then null else $counts.tp / ($counts.tp + $counts.fp) end)
        },
        recall: {
          numerator: $counts.tp,
          denominator: ($counts.tp + $counts.fn),
          decimal: (if ($counts.tp + $counts.fn) == 0 then null else $counts.tp / ($counts.tp + $counts.fn) end)
        },
        specificity: {
          numerator: $counts.tn,
          denominator: ($counts.tn + $counts.fp),
          decimal: (if ($counts.tn + $counts.fp) == 0 then null else $counts.tn / ($counts.tn + $counts.fp) end)
        },
        f1: {
          numerator: (2 * $counts.tp),
          denominator: (2 * $counts.tp + $counts.fp + $counts.fn),
          decimal: (if (2 * $counts.tp + $counts.fp + $counts.fn) == 0 then null else (2 * $counts.tp) / (2 * $counts.tp + $counts.fp + $counts.fn) end)
        },
        balanced_accuracy: {
          decimal: (
            if ($counts.tp + $counts.fn) == 0 or ($counts.tn + $counts.fp) == 0
            then null
            else (($counts.tp / ($counts.tp + $counts.fn)) + ($counts.tn / ($counts.tn + $counts.fp))) / 2
            end
          )
        }
      };
  . as $observations
  | ($historical[0] | map({key: .case_id, value: .outcome}) | from_entries) as $old
  | $observations
  | map(. + {
      historical_outcome: $old[.case_id],
      change: (
        if (($old[.case_id] == "fn" or $old[.case_id] == "fp") and (.outcome == "tp" or .outcome == "tn")) then "corrected"
        elif (($old[.case_id] == "tp" or $old[.case_id] == "tn") and (.outcome == "fn" or .outcome == "fp")) then "regression"
        elif $old[.case_id] == .outcome then "unchanged"
        else "changed"
        end
      )
    }) as $cases
  | {
      schema_version: "secure-engine-phase611-retrospective-v1",
      label: "development-only retrospective rescore",
      independent_holdout: false,
      benchmark_claim: false,
      historical_baseline: {tp: 23, fp: 8, tn: 48, fn: 33},
      metrics: ($cases | metrics),
      by_family: ($cases | sort_by(.family) | group_by(.family) | map({key: .[0].family, value: (metrics)}) | from_entries),
      by_framework: ($cases | sort_by(.framework) | group_by(.framework) | map({key: .[0].framework, value: (metrics)}) | from_entries),
      by_topology: ($cases | sort_by(.topology) | group_by(.topology) | map({key: .[0].topology, value: (metrics)}) | from_entries),
      changes: {
        corrected: ([$cases[] | select(.change == "corrected")] | length),
        regressions: ([$cases[] | select(.change == "regression")] | length),
        changed: ([$cases[] | select(.change == "changed")] | length),
        unchanged: ([$cases[] | select(.change == "unchanged")] | length),
        corrected_cases: [$cases[] | select(.change == "corrected") | {case_id, pair_id, historical_outcome, outcome}],
        regression_cases: [$cases[] | select(.change == "regression") | {case_id, pair_id, historical_outcome, outcome}],
        otherwise_changed_cases: [$cases[] | select(.change == "changed") | {case_id, pair_id, historical_outcome, outcome}]
      },
      cases: $cases
    }
' "$observations" >"$output/results.json"

jq -e '
  .label == "development-only retrospective rescore"
  and (.cases | length == 112)
  and (.metrics.tp + .metrics.fp + .metrics.tn + .metrics.fn == 112)
' "$output/results.json" >/dev/null

(
  cd "$output"
  find raw -type f -name '*.json' -print0 | sort -z | xargs -0 sha256sum >raw-SHA256SUMS
  sha256sum historical-cases.json observations.jsonl raw-SHA256SUMS results.json >SHA256SUMS
)

echo "development-only retrospective rescore complete: $output"
