#!/usr/bin/env python
from __future__ import print_function
from setuptools import setup, find_packages
import os, re

PKG='oauth2'
VERSIONFILE = os.path.join('oauth2', '_version.py')
verstr = "unknown"
try:
    verstrline = open(VERSIONFILE, "rt").read()
except EnvironmentError:
    pass # Okay, there is no version file.
else:
    MVSRE = r"^manual_verstr *= *['\"]([^'\"]*)['\"]"
    mo = re.search(MVSRE, verstrline, re.M)
    if mo:
        mverstr = mo.group(1)
    else:
        print("unable to find version in %s" % (VERSIONFILE))
        raise RuntimeError("if %s.py exists, it must be well-formed" % (VERSIONFILE,))
    AVSRE = r"^auto_build_num *= *['\"]([^'\"]*)['\"]"
    mo = re.search(AVSRE, verstrline, re.M)
    if mo:
        averstr = mo.group(1)
    else:
        averstr = ''
    verstr = '.'.join([mverstr, averstr])

setup(name=PKG,
      version=verstr,
      description="library for OAuth version 1.9",
      author="Joe Stump",
      author_email="joe@simplegeo.com",
      url="http://github.com/joestump/python-oauth2",
      classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: CPython",
        "Development Status :: 5 - Production/Stable",
        "Natural Language :: English",
        "License :: OSI Approved :: MIT License"
      ],
      packages = find_packages(),
      install_requires = ['httplib2'],
      license = "MIT License",
      keywords="oauth",
      zip_safe = True,
      test_suite="tests",
      tests_require=['coverage', 'mock'])
