%{!?_httpd_modconfdir: %{expand: %%global _httpd_modconfdir %%{_sysconfdir}/httpd/conf.d}}
%{!?_httpd_moddir:    %{expand: %%global _httpd_moddir    %%{_libdir}/httpd/modules}}

Name:           mod_wace
Version:        1.1
Release:        1%{?dist}
Summary:        An apache module for adding machine learning capabilities to WAFs and OWASP CRS through WACE

License:        Apache v2.0
URL:            https://github.com/tilsor/ModSecIntl_mod_wace
# Source0:        %{name}-%{version}.tar.gz
Source0:    {{{ git_dir_pack }}}
# TODO: make sure this is accessible:
# Source1:        https://raw.githubusercontent.com/tilsor/ModSecIntl_wace_core/main/wace.proto
Source1:        wace.proto

# glibc-static and libstdc++-static needs "powertools" repo enabled
BuildRequires: gcc, gcc-c++, cmake3 >= 3.15, httpd-devel, libxml2-devel, git, pcre-devel, glibc-static, libstdc++-static
Requires: mod_security < 3, mod_security_crs >= 3
AutoReqProv: no

%description 
WACE is a framework for adding machine learning capabilities to WAFs
(such as mod_security) and OWASP CRS. This package corresponds to the
apache module that communicates mod_security with the WACE core. 

%global debug_package %{nil}

%prep
%autosetup

%build
%define __cmake /usr/bin/cmake3
%cmake -DBUILD_SHARED_LIBS=OFF
%cmake_build
apxs -c -I/usr/include/libxml2 -L%{__cmake_builddir} -lgrpc_wace_client  %{_builddir}/%{name}-%{version}/mod_wace.c

%install
install -Dp -m0755 %{__cmake_builddir}/libgrpc_wace_client.so  %{buildroot}%{_libdir}/libgrpc_wace_client.so
install -Dp -m0755 .libs/mod_wace.so %{buildroot}%{_httpd_moddir}/mod_wace.so
install -Dp -m0644 11-mod_wace.conf %{buildroot}%{_httpd_modconfdir}/11-mod_wace.conf
install -Dp -m0644 crs_rules/REQUEST-904-WACE.conf %{buildroot}%{_sysconfdir}/httpd/modsecurity.d/activated_rules/REQUEST-904-WACE.conf
install -Dp -m0644 crs_rules/REQUEST-949-WACE.conf %{buildroot}%{_sysconfdir}/httpd/modsecurity.d/activated_rules/REQUEST-949-WACE.conf

%files
%{_libdir}/libgrpc_wace_client.so
%{_httpd_moddir}/mod_wace.so
%{_httpd_modconfdir}/11-mod_wace.conf
%{_sysconfdir}/httpd/modsecurity.d/activated_rules/REQUEST-904-WACE.conf
%{_sysconfdir}/httpd/modsecurity.d/activated_rules/REQUEST-949-WACE.conf


%changelog
* Tue Sep 6 2022 Juan Diego Campo <jdcampo@fing.edu.uy>
- Initial release 1.0-1
