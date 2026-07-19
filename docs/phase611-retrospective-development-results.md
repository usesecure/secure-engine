# Phase 6.11 development-only retrospective rescore

## Classification and execution contract

This is a **development-only retrospective rescore** over 112 already opened Phase 19 cases. It is
not an independent holdout, a benchmark result for a release, a ranking, a cross-lane comparison, a
superiority claim, or evidence of production readiness or complete coverage. Any future 0.1.7
evaluation requires a new unseen corpus.

The source was Secure Bench commit `df1cf5f078ec861581f1d11dcc8d4ae35feb0315`, clean before and
after execution. The immutable historical input retained SHA-256
`6266b1c1b064cd15f9f812d66d638eb2edcf0ccac2fbf9162d79134902034185`. The candidate release-mode
binary had SHA-256 `9d2abbece8dd9dd9e34b8d1eee740801900e8ee53e6d991e2a9a61c44cfacea3`.

Each case ran once in its own Secure Engine process. Bubblewrap mounted the filesystem read-only,
made only the external result directory writable, unshared the network namespace, disabled the parse
cache, and left AI in its disabled default. No OpenGrep, Semgrep, Joern, or Ollama process was active
or invoked. The first completed report used Secure Engine's policy exit code 1; it was preserved and
the harness resumed the remaining 111 cases without executing the first case again. The final ledger
contains 112 observations, 112 raw reports, and 112 unique case identifiers.

## Frozen measured result

Historical baseline: TP 23, FP 8, TN 48, FN 33.

| Metric | Development-only retrospective value |
| --- | ---: |
| TP / FP / TN / FN | 45 / 15 / 41 / 11 |
| Precision | 45/60 = 0.750000 |
| Recall | 45/56 = 0.803571 |
| Specificity | 41/56 = 0.732143 |
| F1 | 45/58 = 0.775862 |
| Balanced accuracy | 43/56 = 0.767857 |

The comparison to the immutable historical per-case outcomes was 28 corrected, 13 regressions,
0 otherwise changed, and 71 unchanged. Corrected pair IDs were:

`0007`, `0008`, `0010`, `0011`, `0014`, `0015`, `0017`, `0019`, `0021`, `0022`, `0026`, `0028`,
`0030`, `0032`, `0036`, `0037`, `0038`, `0040`, `0042`, `0043`, `0044`, `0046`, `0047`, `0048`,
`0049`, `0050`, `0051`, and `0052` (all with the `pair-p19-` prefix).

Regressed control pair IDs were `0008`, `0015`, `0021`, `0026`, `0027`, `0032`, `0037`, `0042`,
`0045`, `0046`, `0047`, `0049`, and `0052`. The complete case-level ledger, including opaque case
identifiers and report hashes, remains in the external results artifact.

### By historical family

| Family | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| SE1001 | 8 | 0 | 8 | 0 |
| SE1002 | 8 | 0 | 8 | 0 |
| SE1003 | 0 | 0 | 8 | 8 |
| SE1004 | 8 | 8 | 0 | 0 |
| SE1005 | 6 | 0 | 8 | 2 |
| SE1006 | 7 | 7 | 1 | 1 |
| SE1007 | 8 | 0 | 8 | 0 |

### By framework

| Framework | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| Express | 12 | 4 | 10 | 2 |
| Next App Router | 10 | 3 | 11 | 4 |
| Node | 11 | 4 | 10 | 3 |
| Server Actions | 12 | 4 | 10 | 2 |

### By topology

| Topology | TP | FP | TN | FN |
| --- | ---: | ---: | ---: | ---: |
| Control-flow-sensitive | 10 | 3 | 11 | 4 |
| Direct | 11 | 4 | 10 | 3 |
| Helper-mediated | 12 | 4 | 10 | 2 |
| Inter-file aliased | 12 | 4 | 10 | 2 |

## Preserved evidence and post-measurement action

| Artifact | SHA-256 |
| --- | --- |
| `historical-cases.json` | `169e8c8107c0bb801a39a9f8d98e85dd02104fb64de3602081a97e0c7a5ffab0` |
| `observations.jsonl` | `f6184646b4613ab2ce344b19a9062349d14c540f98058e966c6cf21993d469ad` |
| `raw-SHA256SUMS` | `9412a208b5502971bd1b55db1fdd82843c139b9be3d8d3e6802f3e6726c52b9a` |
| frozen `results.json` | `a1c38646ffc4a7eb9c71355b019ea872adae68db0242f6c0b0d34a9dde1783a8` |

The regressions were all late-round redirect or filesystem controls. Source inspection showed
structured barriers whose constructed-destination/origin or canonical-path/root-boundary semantics
are not yet modeled at the same value precision as the newly reachable sink. Implementing either
barrier would be a third root cause and is outside tranche 1.

Following the frozen protocol, the evidence above was retained. Independent synthetic fixtures then
reproduced long redirect and filesystem controls plus short direct vulnerable pairs. The general
fixed-point correction now permits new late candidates only for rule families with matching barrier
semantics; redirect and filesystem retain the previous candidate budget, while already established
candidates can still be removed by a later proven sanitizer. No case, path, framework, literal,
fingerprint, or benchmark identifier is used in that decision.

The known corpus was not executed again. Therefore the frozen metrics above describe the measured
pre-correction checkpoint, not the final Phase 6.11 tree. Final confidence in the post-measurement
correction comes only from the independent fixtures and complete local quality gates; no claim is
made about an unmeasured final score.

## Final local verification

The final tree passed formatting, strict Clippy, all 143 offline workspace tests, RustSec against
1,166 locally available advisories without fetching, and all cargo-deny advisory, ban, license, and
source checks. Those tests include schema/SARIF compatibility, CLI/desktop parity, cache migration,
determinism, privacy, cancellation, bounds, disabled-by-default AI, and the six focused Phase 6.11
tests. No prohibited scanner or local AI service was active.

The final external release-mode `secure` binary has SHA-256
`f258232632371507f60e7de3ab5d7dc117d6f8b404d1612d404e9af6049272dd`. A no-cache self-scan of
this repository completed without errors or truncation in 2.33 seconds with 318,404 KiB peak RSS;
this is a local engineering check, not corpus evaluation or a performance claim. No RPM or release
artifact was rebuilt.
