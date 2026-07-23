# Phase 6.15 tranche 1 synthetic fixtures

`vulnerable.ts` ignores a local async authorization result and mutates a canonicalized identity.
`control.ts` canonicalizes first and awaits authorization for the exact value used by the mutation.
The examples are independent synthetic code and are not copied from advisories or evaluation data.
