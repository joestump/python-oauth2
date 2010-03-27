#!/usr/bin/env python
#from distutils.core import setup
from setuptools import setup, find_packages

setup(name="oauth2",
      version="1.1.3",
      description="Library for OAuth version 1.0a.",
      author="Joe Stump",
      author_email="joe@simplegeo.com",
      url="http://github.com/simplegeo/python-oauth2",
      packages = find_packages(),
      install_requires = ['httplib2'],
      license = "MIT License",
      keywords="oauth",
      zip_safe = True,
      tests_require=['nose', 'coverage', 'mox'])
