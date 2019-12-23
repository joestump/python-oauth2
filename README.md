[![Join the chat at https://gitter.im/joestump/python-oauth2](https://img.shields.io/badge/gitter-join%20chat-1dce73.svg?style=flat-square)](https://gitter.im/joestump/python-oauth2?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) [![Build Status](http://img.shields.io/travis-ci/joestump/python-oauth2.png?branch=master&style=flat-square)](https://travis-ci.org/joestump/python-oauth2) [![Coverage](https://img.shields.io/codecov/c/github/joestump/python-oauth2.svg?style=flat-square)](https://codecov.io/gh/joestump/python-oauth2) ![Number of issues](https://img.shields.io/github/issues/joestump/python-oauth2.svg?style=flat-square) ![Licence MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)

## Note: This library implements OAuth 1.0 and *not OAuth 2.0*. 

# Overview
python-oauth2 is a python oauth library fully compatible with python versions: 2.6, 2.7, 3.3 and 3.4. This library is depended on by many other downstream packages such as Flask-Oauth.

# Installing

You can install `oauth2` via [the PIP package](https://pypi.python.org/pypi/oauth2). 

    $ pip install oauth2
    
We recommend using [virtualenv](https://virtualenv.pypa.io/en/latest/).

# Examples

Examples can be found in the [wiki](https://github.com/joestump/python-oauth2/wiki)

# Running tests
You can run tests using the following at the command line:

    $ pip install -r requirements.txt
    $ python setup.py test


# History

This code was originally forked from [Leah Culver and Andy Smith's oauth.py code](http://github.com/leah/python-oauth/). Some of the tests come from a [fork by Vic Fryzel](http://github.com/shellsage/python-oauth), while a revamped Request class and more tests were merged in from [Mark Paschal's fork](http://github.com/markpasc/python-oauth). A number of notable differences exist between this code and its forefathers:

* 100% unit test coverage.
* The <code>DataStore</code> object has been completely ripped out. While creating unit tests for the library I found several substantial bugs with the implementation and confirmed with Andy Smith that it was never fully baked.
* Classes are no longer prefixed with <code>OAuth</code>.
* The <code>Request</code> class now extends from <code>dict</code>.
* The library is likely no longer compatible with Python 2.3.
* The <code>Client</code> class works and extends from <code>httplib2</code>. It's a thin wrapper that handles automatically signing any normal HTTP request you might wish to make.
