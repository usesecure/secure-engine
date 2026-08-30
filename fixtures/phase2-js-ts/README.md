# JavaScript and TypeScript scan fixture

This directory is inert analysis input for Secure Engine tests. Do not run `npm install`, `npm ci`, a development server, or application code here. The dependency manifest exists so the scanner can parse a representative JavaScript and TypeScript repository; Secure Engine and its CI do not install or execute these packages.

Dependency versions are kept on patched supported releases to prevent fixture-only Dependabot noise from hiding alerts that affect executable project code.
