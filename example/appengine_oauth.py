"""
The MIT License

Copyright (c) 2010 Justin Plock

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

import os

from google.appengine.ext import webapp
from google.appengine.ext import db
from google.appengine.ext.webapp import util
import oauth2 as oauth # httplib2 is required for this to work on AppEngine

class Client(db.Model):
    # oauth_key is the Model's key_name field
    oauth_secret = db.StringProperty() # str(uuid.uuid4()) works well for this
    first_name = db.StringProperty()
    last_name = db.StringProperty()
    email_address = db.EmailProperty(required=True)
    password = db.StringProperty(required=True)

    @property
    def secret(self):
        return self.oauth_secret

class OAuthHandler(webapp.RequestHandler):

    def __init__(self):
        self._server = oauth.Server()
        self._server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())
        self._server.add_signature_method(oauth.SignatureMethod_PLAINTEXT())

    def get_oauth_request(self):
        """Return an OAuth Request object for the current request."""

        try:
            method = os.environ['REQUEST_METHOD']
        except:
            method = 'GET'

        postdata = None
        if method in ('POST', 'PUT'):
            postdata = self.request.body

        return oauth.Request.from_request(method, self.request.uri,
            headers=self.request.headers, query_string=postdata)

    def get_client(self, request=None):
        """Return the client from the OAuth parameters."""

        if not isinstance(request, oauth.Request):
            request = self.get_oauth_request()
        client_key = request.get_parameter('oauth_consumer_key')
        if not client_key:
            raise Exception('Missing "oauth_consumer_key" parameter in ' \
                'OAuth "Authorization" header')

        client = models.Client.get_by_key_name(client_key)
        if not client:
            raise Exception('Client "%s" not found.' % client_key)

        return client

    def is_valid(self):
        """Returns a Client object if this is a valid OAuth request."""

        try:
            request = self.get_oauth_request()
            client = self.get_client(request)
            params = self._server.verify_request(request, client, None)
        except Exception, e:
            raise e

        return client

class SampleHandler(OAuthHandler):
    def get(self):
        try:
            client = self.is_valid()
        except Exception, e:
            self.error(500)
            self.response.out.write(e)

def main():
    application = webapp.WSGIApplication([(r'/sample', SampleHandler)],
        debug=False)
    util.run_wsgi_app(application)

if __name__ == '__main__':
    main()
