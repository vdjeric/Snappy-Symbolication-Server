Name:           mozilla-snappy
Version:        %{getenv:EPOCH}
Release:        1%{?dist}
Summary:        The Snappy Symbolication Server is a Web server for symbolicating Firefox stacks.
Group:          System Environment/Daemons
License:        MPLv2.0
URL:            %{getenv:UPSTREAM}
Source1:        %{name}.sysconfig
Source2:        %{name}.service
Source3:        %{name}.ini
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  systemd-units
Requires:       systemd, python

%description
The Snappy Symbolication Server is a Web server for symbolicating Firefox stacks. It matches PC addresses to modules in memory and looks up the corresponding function names in server-side symbol files (.SYM files).

If you're interested in setting up local symbols for use with the Gecko profiler for Firefox, the following page will be useful to you:

https://developer.mozilla.org/en/Performance/Profiling_with_the_Built-in_Profiler_and_Local_Symbols_on_Windows

%prep
git clone %{getenv:UPSTREAM} %{_builddir}/snappy-repo

%install
mkdir -p %{buildroot}/%{_bindir}
cp %{_builddir}/snappy-repo/*.py %{buildroot}/%{_bindir}
mkdir -p %{buildroot}/%{_sysconfdir}/sysconfig
cp %{SOURCE1} %{buildroot}/%{_sysconfdir}/sysconfig/%{name}
mkdir -p %{buildroot}/%{_unitdir}
cp %{SOURCE2} %{buildroot}/%{_unitdir}/
cp %{SOURCE3} %{buildroot}/%{_sysconfdir}

%pre

%post
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart %{name}.service

%clean
rm -rf %{_builddir}/snappy-repo
rm -rf %{buildroot}

%files
%defattr(644,root,root,755)
%{_sysconfdir}/%{name}.ini
%{_sysconfdir}/sysconfig/%{name}
%{_unitdir}/%{name}.service
%attr(755, root, root) %{_bindir}/symbolicationWebService.py
%{_bindir}/symFileManager.py
%{_bindir}/symLogging.py
%{_bindir}/symbolicationRequest.py
%doc

%changelog
* Wed Feb 25 2015 Dan Phrawzty <phrawzty@mozilla.com>
- made this spec
