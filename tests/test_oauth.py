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
import sys, os
sys.path[0:0] = [os.path.join(os.path.dirname(__file__), ".."),]

import unittest
import oauth2 as oauth
import random
import time
import urllib
import urlparse
from types import ListType


# Fix for python2.5 compatibility
try:
    from urlparse import parse_qs, parse_qsl
except ImportError:
    from cgi import parse_qs, parse_qsl


class TestError(unittest.TestCase):
    def test_message(self):
        try:
            raise oauth.Error
        except oauth.Error, e:
            self.assertEqual(e.message, 'OAuth error occured.')
        msg = 'OMG THINGS BROKE!!!!'
        try:
            raise oauth.Error(msg)
        except oauth.Error, e:
            self.assertEqual(e.message, msg)

class TestGenerateFunctions(unittest.TestCase):
    def test_build_auth_header(self):
        header = oauth.build_authenticate_header()
        self.assertEqual(header['WWW-Authenticate'], 'OAuth realm=""')
        self.assertEqual(len(header), 1)
        realm = 'http://example.myrealm.com/'
        header = oauth.build_authenticate_header(realm)
        self.assertEqual(header['WWW-Authenticate'], 'OAuth realm="%s"' %
                         realm)
        self.assertEqual(len(header), 1)

    def test_escape(self):
        string = 'http://whatever.com/~someuser/?test=test&other=other'
        self.assert_('~' in oauth.escape(string))
        string = '../../../../../../../etc/passwd'
        self.assert_('../' not in oauth.escape(string))

    def test_gen_nonce(self):
        nonce = oauth.generate_nonce()
        self.assertEqual(len(nonce), 8)
        nonce = oauth.generate_nonce(20)
        self.assertEqual(len(nonce), 20)

    def test_gen_verifier(self):
        verifier = oauth.generate_verifier()
        self.assertEqual(len(verifier), 8)
        verifier = oauth.generate_verifier(16)
        self.assertEqual(len(verifier), 16)

    def test_gen_timestamp(self):
        exp = int(time.time())
        now = oauth.generate_timestamp()
        self.assertEqual(exp, now)

class TestConsumer(unittest.TestCase):
    def setUp(self):
        self.key = 'my-key'
        self.secret = 'my-secret'
        self.consumer = oauth.Consumer(key=self.key, secret=self.secret)

    def test_init(self):
        self.assertEqual(self.consumer.key, self.key)
        self.assertEqual(self.consumer.secret, self.secret)

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, None))
        self.assertRaises(ValueError, lambda: oauth.Consumer('asf', None))
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, 'dasf'))

    def test_str(self):
        res = dict(parse_qsl(str(self.consumer)))
        self.assertTrue('oauth_consumer_key' in res)
        self.assertTrue('oauth_consumer_secret' in res)
        self.assertEquals(res['oauth_consumer_key'], self.consumer.key)
        self.assertEquals(res['oauth_consumer_secret'], self.consumer.secret)

class TestToken(unittest.TestCase):
    def setUp(self):
        self.key = 'my-key'
        self.secret = 'my-secret'
        self.token = oauth.Token(self.key, self.secret)

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.Token(None, None))
        self.assertRaises(ValueError, lambda: oauth.Token('asf', None))
        self.assertRaises(ValueError, lambda: oauth.Token(None, 'dasf'))

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
        v = oauth.generate_verifier()
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
        v = oauth.generate_verifier()
        self.token.set_callback(cb)
        self.token.set_verifier(v)
        url = self.token.get_callback_url()
        verifier_str = '&oauth_verifier=%s' % v
        self.assertEqual(url, '%s%s' % (cb, verifier_str))

        cb = 'http://www.example.com/my-callback-no-query'
        v = oauth.generate_verifier()
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

    def test_to_string(self):
        tok = oauth.Token('tooken', 'seecret')
        self.assertEqual(str(tok), 'oauth_token_secret=seecret&oauth_token=tooken')

    def test_from_string(self):
        self.assertRaises(ValueError, lambda: oauth.Token.from_string(''))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('blahblahblah'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('blah=blah'))

        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token_secret=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=&oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=tooken%26oauth_token_secret=seecret'))

        string = self.token.to_string()
        new = oauth.Token.from_string(string)
        self._compare_tokens(new)

        self.token.set_callback('http://www.example.com/my-callback')
        string = self.token.to_string()
        new = oauth.Token.from_string(string)
        self._compare_tokens(new)

class TestRequest(unittest.TestCase):
    def test_setter(self):
        url = "http://example.com"
        method = "GET"
        req = oauth.Request(method)

        try:
            url = req.url
            self.fail("AttributeError should have been raised on empty url.")
        except AttributeError:
            pass
        except Exception, e:
            self.fail(str(e))

    def test_deleter(self):
        url = "http://example.com"
        method = "GET"
        req = oauth.Request(method, url)

        try:
            del req.url
            url = req.url
            self.fail("AttributeError should have been raised on empty url.")
        except AttributeError:
            pass
        except Exception, e:
            self.fail(str(e))

    def test_url(self):
        url1 = "http://example.com:80/foo.php"
        url2 = "https://example.com:443/foo.php"
        exp1 = "http://example.com/foo.php"
        exp2 = "https://example.com/foo.php"
        method = "GET"

        req = oauth.Request(method, url1)
        self.assertEquals(req.url, exp1)

        req = oauth.Request(method, url2)
        self.assertEquals(req.url, exp2)

    def test_get_parameter(self):
        url = "http://example.com"
        method = "GET"
        params = {'oauth_consumer' : 'asdf'}
        req = oauth.Request(method, url, parameters=params)

        self.assertEquals(req.get_parameter('oauth_consumer'), 'asdf')
        self.assertRaises(oauth.Error, req.get_parameter, 'blah')

    def test_get_nonoauth_parameters(self):

        oauth_params = {
            'oauth_consumer': 'asdfasdfasdf'
        }

        other_params = {
            'foo': 'baz',
            'bar': 'foo',
            'multi': ['FOO','BAR']
        }

        params = oauth_params
        params.update(other_params)

        req = oauth.Request("GET", "http://example.com", params)
        self.assertEquals(other_params, req.get_nonoauth_parameters())

    def test_to_header(self):
        realm = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", realm, params)
        header, value = req.to_header(realm).items()[0]

        parts = value.split('OAuth ')
        vars = parts[1].split(', ')
        self.assertTrue(len(vars), (len(params) + 1))

        res = {}
        for v in vars:
            var, val = v.split('=')
            res[var] = urllib.unquote(val.strip('"'))

        self.assertEquals(realm, res['realm'])
        del res['realm']

        self.assertTrue(len(res), len(params))

        for key, val in res.items():
            self.assertEquals(val, params.get(key))

    def test_to_postdata(self):
        realm = "http://sp.example.com/"

        params = {
            'multi': ['FOO','BAR'],
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", realm, params)

        flat = [('multi','FOO'),('multi','BAR')]
        del params['multi']
        flat.extend(params.items())
        kf = lambda x: x[0]
        self.assertEquals(sorted(flat, key=kf), sorted(parse_qsl(req.to_postdata()), key=kf))

    def test_to_url(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", url, params)
        exp = urlparse.urlparse("%s?%s" % (url, urllib.urlencode(params)))
        res = urlparse.urlparse(req.to_url())
        self.assertEquals(exp.scheme, res.scheme)
        self.assertEquals(exp.netloc, res.netloc)
        self.assertEquals(exp.path, res.path)

        a = parse_qs(exp.query)
        b = parse_qs(res.query)
        self.assertEquals(a, b)

    def test_get_normalized_parameters(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'multi': ['FOO','BAR'],
        }

        req = oauth.Request("GET", url, params)

        res = req.get_normalized_parameters()
        
        srtd = [(k, v if type(v) != ListType else sorted(v)) for k,v in sorted(params.items())]

        self.assertEquals(urllib.urlencode(srtd, True), res)

    def test_get_normalized_parameters_ignores_auth_signature(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_signature': "some-random-signature-%d" % random.randint(1000, 2000),
            'oauth_token': "ad180jjd733klru7",
        }

        req = oauth.Request("GET", url, params)

        res = req.get_normalized_parameters()

        self.assertNotEquals(urllib.urlencode(sorted(params.items())), res)

        foo = params.copy()
        del foo["oauth_signature"]
        self.assertEqual(urllib.urlencode(sorted(foo.items())), res)

    def test_get_normalized_string_escapes_spaces_properly(self):
        url = "http://sp.example.com/"
        params = {
            "some_random_data": random.randint(100, 1000),
            "data": "This data with a random number (%d) has spaces!" % random.randint(1000, 2000),
        }

        req = oauth.Request("GET", url, params)
        res = req.get_normalized_parameters()
        expected = urllib.urlencode(sorted(params.items())).replace('+', '%20')
        self.assertEqual(expected, res)

    def test_sign_request(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200"
        }

        tok = oauth.Token(key="tok-test-key", secret="tok-test-secret")
        con = oauth.Consumer(key="con-test-key", secret="con-test-secret")

        params['oauth_token'] = tok.key
        params['oauth_consumer_key'] = con.key
        req = oauth.Request(method="GET", url=url, parameters=params)

        methods = {
            'TQ6vGQ5A6IZn8dmeGB4+/Jl3EMI=': oauth.SignatureMethod_HMAC_SHA1(),
            'con-test-secret&tok-test-secret': oauth.SignatureMethod_PLAINTEXT()
        }

        for exp, method in methods.items():
            req.sign_request(method, con, tok)
            self.assertEquals(req['oauth_signature_method'], method.name)
            self.assertEquals(req['oauth_signature'], exp)

    def test_from_request(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", url, params)
        headers = req.to_header()

        # Test from the headers
        req = oauth.Request.from_request("GET", url, headers)
        self.assertEquals(req.method, "GET")
        self.assertEquals(req.url, url)

        self.assertEquals(params, req.copy())

        # Test with bad OAuth headers
        bad_headers = {
            'Authorization' : 'OAuth this is a bad header'
        }

        self.assertRaises(oauth.Error, oauth.Request.from_request, "GET",
            url, bad_headers)

        # Test getting from query string
        qs = urllib.urlencode(params)
        req = oauth.Request.from_request("GET", url, query_string=qs)

        exp = parse_qs(qs, keep_blank_values=False)
        for k, v in exp.iteritems():
            exp[k] = urllib.unquote(v[0])

        self.assertEquals(exp, req.copy())

        # Test that a boned from_request() call returns None
        req = oauth.Request.from_request("GET", url)
        self.assertEquals(None, req)

    def test_from_token_and_callback(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        tok = oauth.Token(key="tok-test-key", secret="tok-test-secret")
        req = oauth.Request.from_token_and_callback(tok)
        self.assertFalse('oauth_callback' in req)
        self.assertEquals(req['oauth_token'], tok.key)

        req = oauth.Request.from_token_and_callback(tok, callback=url)
        self.assertTrue('oauth_callback' in req)
        self.assertEquals(req['oauth_callback'], url)

    def test_from_consumer_and_token(self):
        url = "http://sp.example.com/"

        tok = oauth.Token(key="tok-test-key", secret="tok-test-secret")
        con = oauth.Consumer(key="con-test-key", secret="con-test-secret")
        req = oauth.Request.from_consumer_and_token(con, token=tok,
            http_method="GET", http_url=url)

        self.assertEquals(req['oauth_token'], tok.key)
        self.assertEquals(req['oauth_consumer_key'], con.key)

class SignatureMethod_Bad(oauth.SignatureMethod):
    name = "BAD"

    def signing_base(self, request, consumer, token):
        return ""

    def sign(self, request, consumer, token):
        return "invalid-signature"


class TestServer(unittest.TestCase):
    def setUp(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': int(time.time()),
            'bar': 'blerg',
            'multi': ['FOO','BAR'],
            'foo': 59
        }

        self.consumer = oauth.Consumer(key="consumer-key",
            secret="consumer-secret")
        self.token = oauth.Token(key="token-key", secret="token-secret")

        params['oauth_token'] = self.token.key
        params['oauth_consumer_key'] = self.consumer.key
        self.request = oauth.Request(method="GET", url=url, parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        self.request.sign_request(signature_method, self.consumer, self.token)

    def test_init(self):
        server = oauth.Server(signature_methods={'HMAC-SHA1' : oauth.SignatureMethod_HMAC_SHA1()})
        self.assertTrue('HMAC-SHA1' in server.signature_methods)
        self.assertTrue(isinstance(server.signature_methods['HMAC-SHA1'],
            oauth.SignatureMethod_HMAC_SHA1))

        server = oauth.Server()
        self.assertEquals(server.signature_methods, {})

    def test_add_signature_method(self):
        server = oauth.Server()
        res = server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())
        self.assertTrue(len(res) == 1)
        self.assertTrue('HMAC-SHA1' in res)
        self.assertTrue(isinstance(res['HMAC-SHA1'],
            oauth.SignatureMethod_HMAC_SHA1))

        res = server.add_signature_method(oauth.SignatureMethod_PLAINTEXT())
        self.assertTrue(len(res) == 2)
        self.assertTrue('PLAINTEXT' in res)
        self.assertTrue(isinstance(res['PLAINTEXT'],
            oauth.SignatureMethod_PLAINTEXT))

    def test_verify_request(self):
        server = oauth.Server()
        server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        parameters = server.verify_request(self.request, self.consumer,
            self.token)

        self.assertTrue('bar' in parameters)
        self.assertTrue('foo' in parameters)
        self.assertTrue('multi' in parameters)
        self.assertEquals(parameters['bar'], 'blerg')
        self.assertEquals(parameters['foo'], 59)
        self.assertEquals(parameters['multi'], ['FOO','BAR'])

    def test_no_version(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': int(time.time()),
            'bar': 'blerg',
            'multi': ['FOO','BAR'],
            'foo': 59
        }

        self.consumer = oauth.Consumer(key="consumer-key",
            secret="consumer-secret")
        self.token = oauth.Token(key="token-key", secret="token-secret")

        params['oauth_token'] = self.token.key
        params['oauth_consumer_key'] = self.consumer.key
        self.request = oauth.Request(method="GET", url=url, parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        self.request.sign_request(signature_method, self.consumer, self.token)

        server = oauth.Server()
        server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        parameters = server.verify_request(self.request, self.consumer,
            self.token)

    def test_invalid_version(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': '222.9922',
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': int(time.time()),
            'bar': 'blerg',
            'multi': ['foo','bar'],
            'foo': 59
        }

        consumer = oauth.Consumer(key="consumer-key",
            secret="consumer-secret")
        token = oauth.Token(key="token-key", secret="token-secret")

        params['oauth_token'] = token.key
        params['oauth_consumer_key'] = consumer.key
        request = oauth.Request(method="GET", url=url, parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        request.sign_request(signature_method, consumer, token)

        server = oauth.Server()
        server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        self.assertRaises(oauth.Error, server.verify_request, request,
            consumer, token)

    def test_invalid_signature_method(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': '1.0',
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': int(time.time()),
            'bar': 'blerg',
            'multi': ['FOO','BAR'],
            'foo': 59
        }

        consumer = oauth.Consumer(key="consumer-key",
            secret="consumer-secret")
        token = oauth.Token(key="token-key", secret="token-secret")

        params['oauth_token'] = token.key
        params['oauth_consumer_key'] = consumer.key
        request = oauth.Request(method="GET", url=url, parameters=params)

        signature_method = SignatureMethod_Bad()
        request.sign_request(signature_method, consumer, token)

        server = oauth.Server()
        server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        self.assertRaises(oauth.Error, server.verify_request, request,
            consumer, token)

    def test_missing_signature(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': '1.0',
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': int(time.time()),
            'bar': 'blerg',
            'multi': ['FOO','BAR'],
            'foo': 59
        }

        consumer = oauth.Consumer(key="consumer-key",
            secret="consumer-secret")
        token = oauth.Token(key="token-key", secret="token-secret")

        params['oauth_token'] = token.key
        params['oauth_consumer_key'] = consumer.key
        request = oauth.Request(method="GET", url=url, parameters=params)

        signature_method = oauth.SignatureMethod_HMAC_SHA1()
        request.sign_request(signature_method, consumer, token)
        del request['oauth_signature']

        server = oauth.Server()
        server.add_signature_method(oauth.SignatureMethod_HMAC_SHA1())

        self.assertRaises(oauth.MissingSignature, server.verify_request,
            request, consumer, token)


# Request Token: http://oauth-sandbox.sevengoslings.net/request_token
# Auth: http://oauth-sandbox.sevengoslings.net/authorize
# Access Token: http://oauth-sandbox.sevengoslings.net/access_token
# Two-legged: http://oauth-sandbox.sevengoslings.net/two_legged
# Three-legged: http://oauth-sandbox.sevengoslings.net/three_legged
# Key: bd37aed57e15df53
# Secret: 0e9e6413a9ef49510a4f68ed02cd
class TestClient(unittest.TestCase):
#    oauth_uris = {
#        'request_token': '/request_token.php',
#        'access_token': '/access_token.php'
#    }

    oauth_uris = {
        'request_token': '/request_token',
        'authorize': '/authorize',
        'access_token': '/access_token',
        'two_legged': '/two_legged',
        'three_legged': '/three_legged'
    }

    consumer_key = 'bd37aed57e15df53'
    consumer_secret = '0e9e6413a9ef49510a4f68ed02cd'
    host = 'http://oauth-sandbox.sevengoslings.net'

    def setUp(self):
        self.consumer = oauth.Consumer(key=self.consumer_key,
            secret=self.consumer_secret)

        self.body = {
            'foo': 'bar',
            'bar': 'foo',
            'multi': ['FOO','BAR'],
            'blah': 599999
        }

    def _uri(self, type):
        uri = self.oauth_uris.get(type)
        if uri is None:
            raise KeyError("%s is not a valid OAuth URI type." % type)

        return "%s%s" % (self.host, uri)

    def test_access_token_get(self):
        """Test getting an access token via GET."""
        client = oauth.Client(self.consumer, None)
        resp, content = client.request(self._uri('request_token'), "GET")

        self.assertEquals(int(resp['status']), 200)

    def test_access_token_post(self):
        """Test getting an access token via POST."""
        client = oauth.Client(self.consumer, None)
        resp, content = client.request(self._uri('request_token'), "POST")

        self.assertEquals(int(resp['status']), 200)

        res = dict(parse_qsl(content))
        self.assertTrue('oauth_token' in res)
        self.assertTrue('oauth_token_secret' in res)

    def _two_legged(self, method):
        client = oauth.Client(self.consumer, None)

        return client.request(self._uri('two_legged'), method,
            body=urllib.urlencode(self.body))

    def test_two_legged_post(self):
        """A test of a two-legged OAuth POST request."""
        resp, content = self._two_legged("POST")

        self.assertEquals(int(resp['status']), 200)

    def test_two_legged_get(self):
        """A test of a two-legged OAuth GET request."""
        resp, content = self._two_legged("GET")
        self.assertEquals(int(resp['status']), 200)

if __name__ == "__main__":
    unittest.main()

