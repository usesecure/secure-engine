# Fedora RPM packaging

The Fedora-first package contains `secure`, `secure-desktop`, desktop launcher metadata, AppStream metadata, a scalable icon, README, and MIT license. It is built entirely below `target/phase67-rpm`; neither build nor verification installs a system package or changes host configuration.

## Build and automated verification

```bash
packaging/fedora/build-rpm.sh
packaging/fedora/verify-rpm.sh
```

The verifier compares the exact RPM file list, inspects package metadata, extracts with `rpm2cpio`, runs the extracted CLI, validates desktop/AppStream metadata, and keeps the extracted desktop alive for a five-second graphical smoke window. Set `SECURE_SKIP_DESKTOP_SMOKE=1` only in a headless environment; the final Fedora gate must run with a graphical display.

## Installation

```bash
sudo dnf install ./target/phase67-rpm/rpmbuild/RPMS/x86_64/secure-engine-0.1.3-1.fc*.x86_64.rpm
```

## Upgrade

Build or obtain the newer RPM, then run:

```bash
sudo dnf upgrade ./secure-engine-NEW_VERSION.x86_64.rpm
```

## Removal

```bash
sudo dnf remove secure-engine
```

These installation, upgrade, and removal commands are documentation only and are never invoked by automated verification.
