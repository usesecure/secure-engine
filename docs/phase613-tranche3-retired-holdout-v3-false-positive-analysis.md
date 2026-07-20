# Phase 6.13 tranche 3: retired holdout v3 false-positive analysis

## Evidence boundary

This tranche starts from Secure Engine commit
`0e67f70c36d11c67ef6a5e2f8596accf4c437b0d`. Secure Bench commit
`735149c48713ecdf42cc371860ea12809212b647` was inspected only as frozen,
read-only causal evidence. No holdout, runner, adapter, scanner, or scoring
command was executed, and no historical fixture source was copied into Engine
tests. Phase 34 metrics remain historical.

## Exact 16/16 reconciliation

The primary causes below are mutually exclusive. The syntax-valid equation is
`7 = 3 outbound + 2 filesystem + 2 redirect`; the recoverable-syntax equation
is `9 = 3 outbound + 3 filesystem + 3 redirect`; therefore
`16 = 3 + 2 + 2 + 9` with no unclassified observation.

| Historical observation | Syntax | Family | Primary causal class |
| --- | --- | --- | --- |
| `c-ab7c6ca3d643c06e3efe` | valid | redirect | Exact constructed-URL origin guard was not bound to the same redirect value. |
| `c-13f6d66d910287002e2b` | recovered | outbound | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-0701d99b094ffc43fb16` | recovered | filesystem | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-b56af1720d2f3c959bbc` | valid | outbound | Fixed collection wrapper and exact URL-object-to-`href` proof were not preserved together. |
| `c-06138b1e042ed1ae80b0` | valid | filesystem | Separator-aware confinement was not bound to the same resolved candidate. |
| `c-29bd6be097d671d20ab8` | recovered | outbound | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-80b9f58add35876fa5e1` | recovered | redirect | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-80d9fa4ab6569954902d` | recovered | filesystem | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-a81b6ec9f02def668191` | recovered | outbound | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-622ec432953a42cb5ee0` | recovered | redirect | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-e3e4418c034ca70b50d7` | valid | outbound | Fixed collection wrapper and exact URL-object-to-`href` proof were not preserved together. |
| `c-beb55c67dc0884f56676` | valid | outbound | Fixed collection wrapper and exact URL-object-to-`href` proof were not preserved together. |
| `c-263b6e04dd7ff2c3e3f8` | recovered | filesystem | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |
| `c-8cf142e54b6ab443f53d` | valid | redirect | Exact constructed-URL origin guard was not bound to the same redirect value. |
| `c-3af7aecf3cd2c7d1ddb1` | valid | filesystem | Separator-aware confinement was not bound to the same resolved candidate. |
| `c-9f4cd9b4505746065b2b` | recovered | redirect | Program is incomplete at the trailing helper call; recovered facts cannot establish a trustworthy whole-program expectation. |

The requested diagnostic axes are separate from the primary partition:

- syntax recovery: 9 incomplete programs, three per family;
- incorrect source or sink classification: 0; every historical finding had the
  expected family source and sink;
- valid guard not recognized as effective: 7 syntax-valid programs;
- principal/resource identity: 0; these three rules are destination/path
  policies, not authorization rules;
- connectivity/dominance: the mechanism behind the 7 valid-program guard
  failures was loss of the exact derived value or family-specific proof; and
- potentially incorrect corpus expectation: the 9 incomplete programs. A
  parser diagnostic alone proves neither safety nor vulnerability.

## Selected causes and implementation

Two general causes were selected, both within the three syntax-valid outbound
observations:

1. A fixed string collection wrapped by the unshadowed built-in
   `Object.freeze` was not recognized structurally. The wrapper is now unwrapped
   only with one argument, an unshadowed/unreassigned built-in, recursively
   proven fixed strings, and no demonstrated collection mutation before the
   guard. Names do not contribute evidence.
2. An exact protocol-plus-host policy on one constructed `URL` did not carry to
   that same unmodified object's `href`. The proof now records the unique URL
   object and source, requires both exact components on the same object,
   requires a dominant fail-closed guard, and follows only exact object/`href`
   identities through bounded unique local returns.

The two syntax-valid filesystem observations and two syntax-valid redirect
observations map to exact same-value contracts already present at the tranche
base: separator-aware resolved-path confinement and exact constructed-URL
origin identity. This tranche adds independent regression coverage but does not
broaden those contracts.

The nine incomplete programs are deferred. The Engine does not suppress a
finding because parsing recovered. It may honor a structurally complete proof
that survives recovery, and it must retain a finding when recovery preserves a
source-to-sink path without that proof. No claim is made about how the retired
files would score under the current tree.

## Fail-closed limits

The new outbound proof is rejected for shadowed `Object` or `URL`, aliased or
dynamic wrapper dispatch, mutable collections, URL/property mutation,
reassignment, different source identity, different URL objects, spreads,
computed properties, ambiguous aliases, non-dominant or continuing
`catch`/`finally` paths, unsafe conjunctions, cycles, and more than eight proof
steps. Suffix, substring, blocklist, userinfo-only, and nominally suggestive
checks remain insufficient.

Private normalized facts and analysis semantics change, so development cache
v16 replaces v15. V15 and older entries are safe misses and are never
reinterpreted. Public schemas, Evidence Contract v2, secure-json-v1, SARIF,
rule IDs, taxonomy, spans, fingerprint algorithms, CLI/desktop behavior,
privacy, bounds, cancellation, and disabled-by-default AI are unchanged.

## Synthetic coverage

Independent fixtures use new identifiers, literals, and layouts. They cover
clean exact outbound, filesystem, and redirect controls; nearby vulnerable
shadowing, reassignment, ambiguous aliases, mutable collections, shadowed and
aliased wrappers, unsafe conjunctions, spreads, computed properties, URL
mutation, continuing exceptional control, cycles, and depth exhaustion; and a
paired parser-recovery case showing that recovery is neither a global
suppression nor a safety proof. A deterministic cold/warm cache test checks v15
safe miss, v16 reuse, spans, fingerprints, graph/report equality, and Evidence
Contract presence.

## Verification

Rust formatting and strict workspace Clippy (`--all-targets --all-features`,
`-D warnings`) passed. The complete permitted offline workspace suite passed
187 executed tests with zero failures. Exactly the three tests in
`retired_diagnostics_phase67` were excluded by their full test names; no other
test was filtered. The run includes Phase 6.11–6.13, RC2/RC3/RC4/RC5,
schemas, Evidence Contract, SARIF, spans/fingerprints, CLI/desktop, privacy,
bounds, cancellation, deterministic cache/report behavior, and disabled AI.

RustSec checked 427 locked dependencies against 1,166 locally available
advisories without fetching and passed with only the two documented historical
ignores (`RUSTSEC-2026-0194` and `RUSTSEC-2026-0195`). Offline `cargo-deny`
passed advisories, bans, licenses, and sources. No scanner, corpus, packaging,
installation, release, tag, or push command was run.

## Limitations

Static lexical proof does not establish DNS rebinding safety, redirect-chain
policy, runtime mutation hidden behind opaque calls, filesystem symlink/mount
state, or semantics beyond bounded unique resolution. Spreads, computed
properties, reflection, dynamic dispatch, and ambiguous wrappers remain
unresolved. The nine incomplete historical programs remain fixture-reliability
limits rather than measured recoveries.
