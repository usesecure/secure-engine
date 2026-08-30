# Scan-fixture dependency policy

## Purpose and execution boundary

Dependency manifests under `fixtures/` are inert scanner inputs. Secure Engine, its Rust workspace,
and CI do not install, import, build, serve, or execute their declared packages. The manifests exist
to exercise repository inventory and parser behavior against representative JavaScript, TypeScript,
and Python project shapes.

This boundary does not make vulnerable dependency declarations harmless if a person installs them.
Every fixture root therefore contains a warning against installation or execution, and declared
versions are kept on patched supported releases so fixture-only alerts do not obscure executable
workspace risk.

## 2026-08-30 triage

The 63 open GitHub Dependabot alerts attributed to Secure Engine were traced to two scan-fixture
roots:

- `fixtures/phase2-js-ts/package.json`;
- `fixtures/phase5-multilang/python/requirements.txt`.

The aggregate alert distribution was 2 critical, 21 high, 22 medium, and 18 low. All alerts had a
patched version available. No alert was dismissed or reclassified as accepted product risk.

The fixture declarations are updated to:

- Next.js `15.5.21`;
- Flask `3.1.3`;
- Django `5.2.16`.

GitHub must recompute the dependency graph after the change reaches the default branch. Local source
changes alone do not prove that hosted alerts have closed.

## Maintenance gate

When a fixture declaration triggers a dependency alert:

1. confirm that the manifest remains inert and is not referenced by CI, packaging, or a runtime
   build;
2. update to the smallest supported patched version that preserves the fixture's parser shape;
3. run the focused inventory/parser tests and the full Rust verification gates;
4. keep the per-fixture execution warning current;
5. verify the hosted alert state after merge instead of dismissing it solely because it is a
   fixture.

Executable Rust dependencies remain governed separately by `Cargo.lock`, `cargo audit`, and
`cargo deny`.
