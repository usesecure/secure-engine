# Compact scan memory milestone

## Scope

This milestone reduces peak memory for the default compact CLI projection without changing rule
evaluation, finding or abstention authority, conceptual graph totals, output bounds, or the explicit
`--full-graph` contract. The optimization is general: it does not recognize repository names,
packages, paths, or npm-specific source patterns.

The compact path evaluates all retained program records and normalized facts. After rule execution,
fact-only global graph nodes and edges are counted under the same configured bounds but are not
materialized because the compact report would remove them. Finding and abstention evidence remains
materialized and is projected through the existing deterministic compact-report code.

The library's existing `scan_repository` API and the CLI `--full-graph` path continue to construct
the complete graph. The new `scan_repository_compact` API performs the memory-bounded compact path
and returns the final projection directly.

## Measurement protocol

Measurements used the optimized release binary, `/usr/bin/time -v`, cache disabled, and the clean
authorized local npm CLI checkout at revision `b888cc9a9ff34a8b023ff47b784692396635397b`:

```text
NPM_CHECKOUT=/path/to/authorized/npm-cli-security-review
/usr/bin/time -v target/release/secure scan \
  "$NPM_CHECKOUT" \
  --format secure-json-v1 \
  --output /tmp/secure-engine-memory.json \
  --no-cache --quiet
```

Two sequential samples were collected before and after the change. `Maximum resident set size` is
reported by GNU time in KiB. These raw reports and timing files are traceable local evidence; they
were not published as release artifacts.

Measurement environment:

- Linux `7.1.8-200.fc44.x86_64` on `x86_64`;
- `rustc 1.92.0 (ded5c06cf 2025-12-08)` and `cargo 1.92.0`;
- baseline source commit `c5c67cd84a1d39c20f545bc05c9da9e01246e04e`;
- optimized release-binary SHA-256
  `c4b2dbe6c06d7b020c483bbb38b3a26959155cc118e81e2e8c777b7e83d77d4a`;
- optimized source commit `4eee7eeaf34856416f8acc5719d296efbeffd251`.

| Build | Sample | Peak RSS (KiB) | Wall time | Report bytes |
| --- | ---: | ---: | ---: | ---: |
| Baseline `c5c67cd` | 1 | 987,200 | 13.15 s | 2,507,723 |
| Baseline `c5c67cd` | 2 | 987,740 | 11.88 s | 2,507,722 |
| Compact counting path | 1 | 737,624 | 12.02 s | 2,507,722 |
| Compact counting path | 2 | 737,216 | 12.03 s | 2,507,722 |

Mean peak RSS decreased from 987,470 KiB to 737,420 KiB, a reduction of approximately 25.3%.
Wall-clock results remain within ordinary run-to-run variation and are not presented as a speedup.

One separate `--full-graph` sample retained all 57,748 facts, 208,157 nodes, and 368,627 edges. It
peaked at 987,192 KiB and produced a 539,259,886-byte report. End-to-end time was 230.51 seconds
under heavy filesystem pressure, so this single full-export sample is contract evidence rather than
a speed benchmark. Its distinct full-report fingerprint was
`f024e99f337ff2ca185e603f8967964b63ebeacefa1853614fbcf4c5a0bb6bb7`.

## Equivalence evidence

The before and after reports preserved:

- report fingerprint `0c76afa4aa89f99d7c48bc08edc37f8e7e375a46ebb00aa43149f78bd3635b82`;
- 4,847 scanned files and 57,748 normalized facts;
- 208,157 conceptual graph nodes and 368,627 conceptual graph edges;
- zero findings and three explicit abstentions;
- 14 retained evidence-neighborhood facts;
- the 64 MiB output budget and a 2.51 MB compact report;
- byte-equivalent normalized JSON after removing documented volatile timestamps and durations.

The regression suite also compares a direct compact scan with a full scan projected afterward,
including graph evidence, facts, findings, abstentions, totals, truncation state, projection metadata,
and stable report fingerprint.

## Residual limits

- Peak memory is still approximately 737 MiB for this checkout. Program-record extraction and
  bounded fixed-point analysis remain the largest retained stages and need separate profiling.
- The optimization does not reduce `--full-graph` memory because that mode explicitly requests all
  graph evidence.
- These measurements describe one checkout and workstation. They are traceable local evidence,
  not independently reproduced evidence or a universal resource guarantee.
- A zero-finding result is not a security verdict. The three abstentions still require human review.
