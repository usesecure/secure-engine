# VS Code Go lead-quality fixtures

This fixture set models the first SecureFlow campaign defects without copying private source.

- `lint-config.ts`, `binary-path.ts`, and `local-debug.ts` reproduce ordinary configuration flowing through a shared helper while unrelated clean calls reach two local diagnostic sinks.
- `survey-state.ts` reproduces ordinary extension state reaching an explicit local diagnostic command.
- `positive-secrets.ts` retains local and remote SE1010 positive controls and exercises call-site return binding.
- `network-listener.ts` models a transient Node `net.Server.listen(port)` receiver plus explicit-loopback and unproven-import controls.
- `package.json` declares that the fixture extension does not support untrusted workspaces.

The listener is a modeling lead, not a vulnerability fixture. Reachability, interface selection, port discovery, race outcome, firewall policy, protocol impact, and duplicate status all require human validation.
