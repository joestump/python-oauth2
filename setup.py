#!/usr/bin/env python
#from distutils.core import setup
from setuptools import setup, find_packages

setup(name="oauth",
      version="1.0.1a",
      description="Library for OAuth version 1.0a.",
      author="Leah Culver",
      author_email="leah.culver@gmail.com",
      url="http://code.google.com/p/oauth",
      packages = find_packages(),
      license = "MIT License",
      zip_safe = True)