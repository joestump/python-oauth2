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

import httplib2
import oauth2
import urllib

class Client(httplib2.Http):
    """OAuthClient is a worker to attempt to execute a request."""

    def __init__(self, consumer, token=None, cache=None, timeout=None,
        proxy_info=None):

        if consumer is not None and not isinstance(consumer, oauth2.Consumer):
            raise ValueError("Invalid consumer.")

        if token is not None and not isinstance(token, oauth2.Token):
            raise ValueError("Invalid token.")

        self.consumer = consumer
        self.token = token
        self.method = oauth2.SignatureMethod_HMAC_SHA1()

        httplib2.Http.__init__(self, cache=cache, timeout=timeout, proxy_info=proxy_info)

    def set_signature_method(self, method):
        if not isinstance(method, oauth2.SignatureMethod):
            raise ValueError("Invalid signature method.")

        self.method = method

    def request(self, uri, method="GET", body='', headers=None, 
        redirections=httplib2.DEFAULT_MAX_REDIRECTS, connection_type=None):
        DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

        if not isinstance(headers, dict):
            headers = {}

        if method == "POST":
            headers['Content-Type'] = headers.get('Content-Type', 
                DEFAULT_POST_CONTENT_TYPE)

        is_form_encoded = \
            headers.get('Content-Type') == 'application/x-www-form-urlencoded'

        if is_form_encoded and body:
            parameters = oauth2.parse_qs(body)
        else:
            parameters = None

        req = oauth2.Request.from_consumer_and_token(self.consumer, 
            token=self.token, http_method=method, http_url=uri, 
            parameters=parameters, body=body, is_form_encoded=is_form_encoded)

        req.sign_request(self.method, self.consumer, self.token)

        schema, rest = urllib.splittype(uri)
        if rest.startswith('//'):
            hierpart = '//'
        else:
            hierpart = ''
        host, rest = urllib.splithost(rest)

        realm = schema + ':' + hierpart + host

        if is_form_encoded:
            body = req.to_postdata()
        elif method == "GET":
            uri = req.to_url()
        else:
            headers.update(req.to_header(realm=realm))

        return httplib2.Http.request(self, uri, method=method, body=body,
            headers=headers, redirections=redirections,
            connection_type=connection_type)

