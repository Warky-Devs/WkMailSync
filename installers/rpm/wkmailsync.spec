# Maintainer: Hein Puth (Warky Devs)
Name:           wkmailsync
Version:        1.0.9
Release:        1%{?dist}
Summary:        Mail synchronization and backup tool - IMAP/Maildir sync and export
License:        GPL-3.0-only
URL:            https://github.com/Warky-Devs/WkMailSync
Source0:        %{url}/archive/v%{version}/wkmailsync-%{version}.tar.gz

BuildRequires:  golang >= 1.22.0

%description
Mail synchronization and backup tool supporting IMAP/Maildir sync and export.
Supports IMAP-to-IMAP, IMAP-to-EML, Maildir-to-EML/Zip, and Virtualmin bulk export.

%prep
%autosetup -n wkmailsync-%{version}

%build
export GOPATH=%{_builddir}/go
go build -trimpath \
    -ldflags "-s -w" \
    -o %{name} ./cmd/wkmailsync

%install
install -Dm755 %{name} %{buildroot}%{_bindir}/%{name}

%files
%license LICENSE
%{_bindir}/%{name}

%changelog
* Thu Mar 13 2026 Hein Puth (Warky Devs) - 1.0.3-1
- Initial package
