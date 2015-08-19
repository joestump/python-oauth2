"""
The MIT License

Copyright (c) 2007 Leah Culver

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

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import urllib

import oauth2

# fake urls for the test server
REQUEST_TOKEN_URL = 'https://photos.example.net/request_token'
ACCESS_TOKEN_URL = 'https://photos.example.net/access_token'
AUTHORIZATION_URL = 'https://photos.example.net/authorize'
CALLBACK_URL = 'http://printer.example.com/request_token_ready'
RESOURCE_URL = 'http://photos.example.net/photos'
REALM = 'http://photos.example.net/'
VERIFIER = 'verifier'

# example store for one of each thing
class MockDataStore(object):

    def __init__(self):
        self.consumer = oauth2.Consumer('key', 'secret')
        self.request_token = oauth2.Token('requestkey', 'requestsecret')
        self.access_token = oauth2.Token('accesskey', 'accesssecret')
        self.nonce = 'nonce'
        self.verifier = VERIFIER

    def lookup_consumer(self, key):
        if key == self.consumer.key:
            return self.consumer
        return None

    def lookup_token(self, token_type, token):
        token_attrib = getattr(self, '%s_token' % token_type)
        if token == token_attrib.key:
            ## HACK
            token_attrib.set_callback(CALLBACK_URL)
            return token_attrib
        return None

    def lookup_nonce(self, consumer, token, nonce):
        if token and consumer.key == self.consumer.key and (token.key == self.request_token.key or token.key == self.access_token.key) and nonce == self.nonce:
            return self.nonce
        return None

    def fetch_request_token(self, consumer, callback):
        if consumer.key == self.consumer.key:
            if callback:
                # want to check here if callback is sensible
                # for mock store, we assume it is
                self.request_token.set_callback(callback)
            return self.request_token
        return None

    def fetch_access_token(self, consumer, token, verifier):
        if consumer.key == self.consumer.key and token.key == self.request_token.key and verifier == self.verifier:
            # want to check here if token is authorized
            # for mock store, we assume it is
            return self.access_token
        return None

    def authorize_request_token(self, token, user):
        if token.key == self.request_token.key:
            # authorize the request token in the store
            # for mock store, do nothing
            return self.request_token
        return None

class DataStoreServer(oauth2.Server):
    """
    Adds data storage abilities to the base OAuth Server
    """
    def __init__(self, signature_methods=None, data_store=None):
        self.data_store = data_store
        super(DataStoreServer, self).__init__(signature_methods)

    def fetch_request_token(self, oauth_request):
        """Processes a request_token request and returns the
        request token on success.
        """
        try:
            # Get the request token for authorization.
            token = self._get_token(oauth_request, 'request')
        except oauth2.Error:
            # No token required for the initial token request.
            version = self._get_version(oauth_request)
            consumer = self._get_consumer(oauth_request)
            try:
                callback = self.get_callback(oauth_request)
            except oauth2.Error:
                callback = None # 1.0, no callback specified.
            self._check_signature(oauth_request, consumer, None)
            # Fetch a new token.
            token = self.data_store.fetch_request_token(consumer, callback)
        return token

    def fetch_access_token(self, oauth_request):
        """Processes an access_token request and returns the
        access token on success.
        """
        version = self._get_version(oauth_request)
        consumer = self._get_consumer(oauth_request)
        try:
            verifier = self._get_verifier(oauth_request)
        except oauth2.Error:
            verifier = None
        # Get the request token.
        token = self._get_token(oauth_request, 'request')
        self._check_signature(oauth_request, consumer, token)
        new_token = self.data_store.fetch_access_token(consumer, token, verifier)
        return new_token

    def authorize_token(self, token, user):
        """Authorize a request token."""
        return self.data_store.authorize_request_token(token, user)

    def get_callback(self, oauth_request):
        """Get the callback URL."""
        return oauth_request.get_parameter('oauth_callback')

    def _get_consumer(self, oauth_request):
        consumer_key = oauth_request.get_parameter('oauth_consumer_key')
        consumer = self.data_store.lookup_consumer(consumer_key)
        if not consumer:
            raise OAuthError('Invalid consumer.')
        return consumer

    def _get_token(self, oauth_request, token_type='access'):
        """Try to find the token for the provided request token key."""
        token_field = oauth_request.get_parameter('oauth_token')
        token = self.data_store.lookup_token(token_type, token_field)
        if not token:
            raise OAuthError('Invalid %s token: %s' % (token_type, token_field))
        return token



class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.oauth_server = DataStoreServer(data_store=MockDataStore())
        self.oauth_server.add_signature_method(oauth2.SignatureMethod_PLAINTEXT())
        self.oauth_server.add_signature_method(oauth2.SignatureMethod_HMAC_SHA1())
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    # example way to send an oauth error
    def send_error(self, err=None):
        # send a 401 error
        self.send_error(401, str(err.message))
        # return the authenticate header
        header = oauth2.build_authenticate_header(realm=REALM)
        for k, v in header.iteritems():
            self.send_header(k, v)

    def do_GET(self):

        # debug info
        #print self.command, self.path, self.headers

        # get the post data (if any)
        postdata = None
        if self.command == 'POST':
            try:
                length = int(self.headers.getheader('content-length'))
                postdata = self.rfile.read(length)
            except:
                pass

        # construct the oauth request from the request parameters
        oauth_request = oauth2.Request.from_request(self.command, self.path, headers=self.headers, query_string=postdata)

        # request token
        if self.path.startswith(REQUEST_TOKEN_URL):
            try:
                # create a request token
                token = self.oauth_server.fetch_request_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except oauth2.Error, err:
                self.send_error(err)
            return

        # user authorization
        if self.path.startswith(AUTHORIZATION_URL):
            try:
                # get the request token
                token = self.oauth_server.fetch_request_token(oauth_request)
                # authorize the token (kind of does nothing for now)
                token = self.oauth_server.authorize_token(token, None)
                token.set_verifier(VERIFIER)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the callback url (to show server has it)
                self.wfile.write(token.get_callback_url())
            except oauth2.Error, err:
                self.send_error(err)
            return

        # access token
        if self.path.startswith(ACCESS_TOKEN_URL):
            try:
                # create an access token
                token = self.oauth_server.fetch_access_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except oauth2.Error, err:
                self.send_error(err)
            return

        # protected resources
        if self.path.startswith(RESOURCE_URL):
            try:
                # verify the request has been oauth authorized
                consumer = self.oauth_server._get_consumer(oauth_request)
                token = self.oauth_server._get_token(oauth_request, 'access')
                params = self.oauth_server.verify_request(oauth_request, consumer, token)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the extra parameters - just for something to return
                self.wfile.write(str(params))
            except oauth2.Error, err:
                self.send_error(err)
            return

    def do_POST(self):
        return self.do_GET()

def main():
    try:
        server = HTTPServer(('', 8080), RequestHandler)
        print 'Test server running...'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()