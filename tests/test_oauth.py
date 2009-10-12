"""
The MIT License
 
Copyright (c) 2009 Vic Fryzel
 
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

import unittest

from oauth import *

class TestOAuthError(unittest.TestCase):
    def test_message(self):
        try:
            raise OAuthError
        except OAuthError, e:
            self.assertEqual(e.message, 'OAuth error occured.')
        msg = 'OMG THINGS BROKE!!!!'
        try:
            raise OAuthError(msg)
        except OAuthError, e:
            self.assertEqual(e.message, msg)

class TestGenerateFunctions(unittest.TestCase):
    def test_build_auth_header(self):
        header = build_authenticate_header()
        self.assertEqual(header['WWW-Authenticate'], 'OAuth realm=""')
        self.assertEqual(len(header), 1)
        realm = 'http://example.myrealm.com/'
        header = build_authenticate_header(realm)
        self.assertEqual(header['WWW-Authenticate'], 'OAuth realm="%s"' %
                         realm)
        self.assertEqual(len(header), 1)
    
    def test_escape(self):
        string = 'http://whatever.com/~someuser/?test=test&other=other'
        self.assert_('~' in escape(string))
        string = '../../../../../../../etc/passwd'
        self.assert_('../' not in escape(string))

    def test_gen_nonce(self):
        nonce = generate_nonce()
        self.assertEqual(len(nonce), 8)
        nonce = generate_nonce(20)
        self.assertEqual(len(nonce), 20)

    def test_gen_verifier(self):
        verifier = generate_verifier()
        self.assertEqual(len(verifier), 8)
        verifier = generate_verifier(16)
        self.assertEqual(len(verifier), 16)

class TestOAuthConsumer(unittest.TestCase):
    def test_init(self):
        key = 'my-key'
        secret = 'my-secret'
        consumer = OAuthConsumer(key, secret)
        self.assertEqual(consumer.key, key)
        self.assertEqual(consumer.secret, secret)

class TestOAuthToken(unittest.TestCase):
    def setUp(self):
        self.key = 'my-key'
        self.secret = 'my-secret'
        self.token = OAuthToken(self.key, self.secret)

    def test_init(self):
        self.assertEqual(self.token.key, self.key)
        self.assertEqual(self.token.secret, self.secret)
        self.assertEqual(self.token.callback, None)
        self.assertEqual(self.token.callback_confirmed, None)
        self.assertEqual(self.token.verifier, None)

    def test_set_callback(self):
        self.assertEqual(self.token.callback, None)
        self.assertEqual(self.token.callback_confirmed, None)
        cb = 'http://www.example.com/my-callback'
        self.token.set_callback(cb)
        self.assertEqual(self.token.callback, cb)
        self.assertEqual(self.token.callback_confirmed, 'true')
        self.token.set_callback(None)
        self.assertEqual(self.token.callback, None)
        # TODO: The following test should probably not pass, but it does
        #       To fix this, check for None and unset 'true' in set_callback
        #       Additionally, should a confirmation truly be done of the callback?
        self.assertEqual(self.token.callback_confirmed, 'true')

    def test_set_verifier(self):
        self.assertEqual(self.token.verifier, None)
        v = generate_verifier()
        self.token.set_verifier(v)
        self.assertEqual(self.token.verifier, v)
        self.token.set_verifier()
        self.assertNotEqual(self.token.verifier, v)
        self.token.set_verifier('')
        self.assertEqual(self.token.verifier, '')

    def test_get_callback_url(self):
        self.assertEqual(self.token.get_callback_url(), None)

        self.token.set_verifier()
        self.assertEqual(self.token.get_callback_url(), None)

        cb = 'http://www.example.com/my-callback?save=1&return=true'
        v = generate_verifier()
        self.token.set_callback(cb)
        self.token.set_verifier(v)
        url = self.token.get_callback_url()
        verifier_str = '&oauth_verifier=%s' % v
        self.assertEqual(url, '%s%s' % (cb, verifier_str))

        cb = 'http://www.example.com/my-callback-no-query'
        v = generate_verifier()
        self.token.set_callback(cb)
        self.token.set_verifier(v)
        url = self.token.get_callback_url()
        verifier_str = '?oauth_verifier=%s' % v
        self.assertEqual(url, '%s%s' % (cb, verifier_str))

    def test_to_string(self):
        string = 'oauth_token_secret=%s&oauth_token=%s' % (self.secret,
                                                           self.key)
        self.assertEqual(self.token.to_string(), string)

        self.token.set_callback('http://www.example.com/my-callback')
        string += '&oauth_callback_confirmed=true'
        self.assertEqual(self.token.to_string(), string)

    def _compare_tokens(self, new):
        self.assertEqual(self.token.key, new.key)
        self.assertEqual(self.token.secret, new.secret)
        # TODO: What about copying the callback to the new token?
        # self.assertEqual(self.token.callback, new.callback)
        self.assertEqual(self.token.callback_confirmed,
                         new.callback_confirmed)
        # TODO: What about copying the verifier to the new token?
        # self.assertEqual(self.token.verifier, new.verifier)

    def test_from_string(self):
        string = self.token.to_string()
        new = OAuthToken.from_string(string)
        self._compare_tokens(new)

        self.token.set_callback('http://www.example.com/my-callback')
        string = self.token.to_string()
        new = OAuthToken.from_string(string)
        self._compare_tokens(new)

class TestOAuthRequest(unittest.TestCase):
    pass

class TestOAuthServer(unittest.TestCase):
    pass

class TestOAuthClient(unittest.TestCase):
    pass

class TestOAuthDataStore(unittest.TestCase):
    pass

class TestOAuthSignatureMethod(unittest.TestCase):
    pass

class TestOAuthSignatureMethod_HMAC_SHA1(unittest.TestCase):
    pass

class TestOAuthSignatureMethod_PLAINTEXT(unittest.TestCase):
    pass

