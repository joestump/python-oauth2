%include %{_rpmconfigdir}/macros.python


Name:           python-oauth2
Version:        1.2.1
Release:        1%{?dist}
Summary:        A fully tested, abstract interface to creating OAuth clients and servers

Group:          Development/Libraries/Python
License:        MIT
Vendor:         SimpleGeo Nerds <nerds@simplegeo.com>
URL:            http://github.com/simplegeo/python-oauth2
Source0:        http://github.com/simplegeo/python-oauth2/tarball/%{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

BuildRequires:  python-devel
BuildRequires:  python-markdown2
%if 0%{?fedora} >= 8
BuildRequires:  python-setuptools-devel
%else
BuildRequires:  python-setuptools
%endif
Requires:       python-httplib2, python-simplejson

%description
This code was originally forked from Leah Culver and Andy Smith's oauth.py code.

Some of the tests come from a fork by Vic Fryzel, while a revamped Request class
and more tests were merged in from Mark Paschal's fork.

%prep
%setup -q -n %{name}-%{version}


%build
%{__python} setup.py build
# Build README.html
markdown2 README.md > README.html


%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}
%{__python} setup.py install -O1 --skip-build --root %{buildroot}


%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc README.md README.html
%{py_sitedir}/*


%changelog
* Fri Jul 9 2010 Jorge A Gallegos <kad@blegh.net> - 1.2.1-1
- First spec draft

