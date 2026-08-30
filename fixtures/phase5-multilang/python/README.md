# Python scan fixture

This directory is inert analysis input for Secure Engine tests. Do not create an environment, install `requirements.txt`, start a server, or execute the fixture applications. The requirements file exists so the scanner can parse a representative Python repository; Secure Engine and its CI do not install or import these packages.

Dependency versions are kept on patched supported releases to prevent fixture-only Dependabot noise from hiding alerts that affect executable project code.
