Name:           secure-engine
Version:        0.1.5
Release:        1%{?dist}
Summary:        Local deterministic security analysis CLI and native desktop
License:        MIT
URL:            https://github.com/usesecure/secure-engine
Source0:        %{name}-%{version}.tar.gz
BuildArch:      x86_64

%description
Secure Engine provides a local-first security analysis CLI and native desktop
application with deterministic evidence paths, baselines, history, JSON, and
SARIF output. Optional AI-assisted validation is disabled by default and
requires an exact payload preview and explicit consent.

%global _build_id_links none
%global debug_package %{nil}

%prep
%setup -q

%build
# Release binaries are built by the unprivileged packaging driver before rpmbuild.

%install
install -Dpm0755 secure %{buildroot}%{_bindir}/secure
install -Dpm0755 secure-desktop %{buildroot}%{_bindir}/secure-desktop
install -Dpm0644 dev.usesecure.SecureEngine.desktop %{buildroot}%{_datadir}/applications/dev.usesecure.SecureEngine.desktop
install -Dpm0644 dev.usesecure.SecureEngine.metainfo.xml %{buildroot}%{_metainfodir}/dev.usesecure.SecureEngine.metainfo.xml
install -Dpm0644 dev.usesecure.SecureEngine.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/dev.usesecure.SecureEngine.svg

%check
%{buildroot}%{_bindir}/secure rules list >/dev/null
%{buildroot}%{_bindir}/secure ai providers >/dev/null
desktop-file-validate %{buildroot}%{_datadir}/applications/dev.usesecure.SecureEngine.desktop
appstreamcli validate --no-net %{buildroot}%{_metainfodir}/dev.usesecure.SecureEngine.metainfo.xml

%files
%license LICENSE
%doc README.md
%{_bindir}/secure
%{_bindir}/secure-desktop
%{_datadir}/applications/dev.usesecure.SecureEngine.desktop
%{_metainfodir}/dev.usesecure.SecureEngine.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/dev.usesecure.SecureEngine.svg

%changelog
* Fri Jul 17 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.5-1
- Phase 6.9 retired Phase 15 evidence and false-positive remediation

* Fri Jul 17 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.4-1
- Phase 6.8 retired-evidence precision and evidence-path remediation

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.3-1
- Phase 6.7 public evidence-contract-v2 conformance and generalized remediation

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.2-1
- Phase 6.6 explicit evidence semantics and precision hardening

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.1-1
- Phase 6.5 neutral taxonomy and deterministic precision calibration

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.0-1
- Phase 6 optional consented AI-assisted finding validation

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.0-1
- Phase 5 Rust, Python, Go, and mixed-monorepo analysis

* Thu Jul 16 2026 Secure Engine maintainers <security@usesecure.dev> - 0.1.0-1
- Phase 4 local CLI and native desktop MVP
