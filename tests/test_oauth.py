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
import oauth
import time
import urllib
import urlparse
import cgi

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
    def test_init(self):
        key = 'my-key'
        secret = 'my-secret'
        consumer = oauth.Consumer(key, secret)
        self.assertEqual(consumer.key, key)
        self.assertEqual(consumer.secret, secret)

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, None))
        self.assertRaises(ValueError, lambda: oauth.Consumer('asf', None))
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, 'dasf'))

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

    def test_get_nonoauth_parameters(self):

        oauth_params = {
            'oauth_consumer': 'asdfasdfasdf'
        }
        
        other_params = {
            'foo': 'baz',
            'bar': 'foo'
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
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", realm, params)
        
        self.assertEquals(params, dict(urlparse.parse_qsl(req.to_postdata())))

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

        a = urlparse.parse_qs(exp.query)
        b = urlparse.parse_qs(res.query)
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
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", url, params)

        res = dict(urlparse.parse_qsl(req.get_normalized_parameters()))

        foo = params.copy()
        del foo['oauth_signature']
        self.assertEquals(foo, res)
        
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
            print req.copy()
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
        
        exp = cgi.parse_qs(qs, keep_blank_values=False)
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

class TestServer(unittest.TestCase):
    def test_init(self):
        server = oauth.Server(signature_methods={'HMAC-SHA1' : oauth.SignatureMethod_HMAC_SHA1()})
        self.assertTrue('HMAC-SHA1' in server.signature_methods)
        self.assertTrue(isinstance(server.signature_methods['HMAC-SHA1'], 
            oauth.SignatureMethod_HMAC_SHA1))

        server = oauth.Server()
        self.assertEquals(server.signature_methods, {})

    def _req(self):
        ds = MyDataStore()

        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200"
        }

        con = ds.lookup_consumer("test-consumer-key")
        tok = ds.lookup_token(con, "request", "test-request-token-key")

        params['oauth_token'] = tok.key
        params['oauth_consumer_key'] = con.key
        return oauth.Request(method="GET", url=url, parameters=params)

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

    def test_fetch_request_token(self):
        pass

#        server = oauth.Server(data_store=MyDataStore())
#        token = server.fetch_request_token(self._req())

    def test_bad_token_fetch_request_token(self):
        pass

class TestClient(unittest.TestCase):
    pass

class TestDataStore(unittest.TestCase):
    pass

class TestSignatureMethod(unittest.TestCase):
    pass

class TestSignatureMethod_HMAC_SHA1(unittest.TestCase):
    pass

class TestSignatureMethod_PLAINTEXT(unittest.TestCase):
    pass

