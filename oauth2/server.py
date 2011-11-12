"""
The MIT License

Copyright (c) 2007-2010 Leah Culver, Joe Stump, Mark Paschal, Vic Fryzel

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import oauth2
import time

class Server(object):
    """A skeletal implementation of a service provider, providing protected
    resources to requests from authorized consumers.
 
    This class implements the logic to check requests for authorization. You
    can use it with your web server or web framework to protect certain
    resources with OAuth.
    """

    timestamp_threshold = 300 # In seconds, five minutes.
    version = oauth2.OAUTH_VERSION
    signature_methods = None

    def __init__(self, signature_methods=None):
        self.signature_methods = signature_methods or {}

    def add_signature_method(self, signature_method):
        self.signature_methods[signature_method.name] = signature_method
        return self.signature_methods

    def verify_request(self, request, consumer, token):
        """Verifies an api call and checks all the parameters."""

        self._check_version(request)
        self._check_signature(request, consumer, token)
        parameters = request.get_nonoauth_parameters()
        return parameters

    def build_authenticate_header(self, realm=''):
        """Optional support for the authenticate header."""
        return {'WWW-Authenticate': 'OAuth realm="%s"' % realm}

    def _check_version(self, request):
        """Verify the correct version of the request for this server."""
        version = self._get_version(request)
        if version and version != self.version:
            raise oauth2.Error('OAuth version %s not supported.' % str(version))

    def _get_version(self, request):
        """Return the version of the request for this server."""
        try:
            version = request.get_parameter('oauth_version')
        except:
            version = oauth2.OAUTH_VERSION

        return version

    def _get_signature_method(self, request):
        """Figure out the signature with some defaults."""
        try:
            signature_method = request.get_parameter('oauth_signature_method')
        except:
            signature_method = oauth2.SIGNATURE_METHOD

        try:
            # Get the signature method object.
            signature_method = self.signature_methods[signature_method]
        except:
            signature_method_names = ', '.join(self.signature_methods.keys())
            raise oauth2.Error('Signature method %s not supported try one of the following: %s' % (signature_method, signature_method_names))

        return signature_method

    def _get_verifier(self, request):
        return request.get_parameter('oauth_verifier')

    def _check_signature(self, request, consumer, token):
        timestamp, nonce = request._get_timestamp_nonce()
        self._check_timestamp(timestamp)
        signature_method = self._get_signature_method(request)

        try:
            signature = request.get_parameter('oauth_signature')
        except:
            raise oauth2.MissingSignature('Missing oauth_signature.')

        # Validate the signature.
        valid = signature_method.check(request, consumer, token, signature)

        if not valid:
            key, base = signature_method.signing_base(request, consumer, token)

            raise oauth2.Error('Invalid signature. Expected signature base ' 
                'string: %s' % base)

    def _check_timestamp(self, timestamp):
        """Verify that timestamp is recentish."""
        timestamp = int(timestamp)
        now = int(time.time())
        lapsed = now - timestamp
        if lapsed > self.timestamp_threshold:
            raise oauth2.Error('Expired timestamp: given %d and now %s has a '
                'greater difference than threshold %d' % (timestamp, now, 
                    self.timestamp_threshold))

