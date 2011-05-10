# -*- coding: utf-8 -*-

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
import sys
import os
import unittest
import oauth2 as oauth
import random
import time
import urllib
import urlparse
from types import ListType
import mock
import httplib2

# Fix for python2.5 compatibility
try:
    from urlparse import parse_qs, parse_qsl
except ImportError:
    from cgi import parse_qs, parse_qsl


sys.path[0:0] = [os.path.join(os.path.dirname(__file__), ".."),]


class TestError(unittest.TestCase):
    def test_message(self):
        try:
            raise oauth.Error
        except oauth.Error, e:
            self.assertEqual(e.message, 'OAuth error occurred.')

        msg = 'OMG THINGS BROKE!!!!'
        try:
            raise oauth.Error(msg)
        except oauth.Error, e:
            self.assertEqual(e.message, msg)

    def test_str(self):
        try:
            raise oauth.Error
        except oauth.Error, e:
            self.assertEquals(str(e), 'OAuth error occurred.')

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

    def test_build_xoauth_string(self):
        consumer = oauth.Consumer('consumer_token', 'consumer_secret')
        token = oauth.Token('user_token', 'user_secret')
        url = "https://mail.google.com/mail/b/joe@example.com/imap/"
        xoauth_string = oauth.build_xoauth_string(url, consumer, token)

        method, oauth_url, oauth_string = xoauth_string.split(' ')

        self.assertEqual("GET", method)
        self.assertEqual(url, oauth_url)

        returned = {}
        parts = oauth_string.split(',')
        for part in parts:
            var, val = part.split('=')
            returned[var] = val.strip('"') 

        self.assertEquals('HMAC-SHA1', returned['oauth_signature_method'])
        self.assertEquals('user_token', returned['oauth_token'])
        self.assertEquals('consumer_token', returned['oauth_consumer_key'])
        self.assertTrue('oauth_signature' in returned, 'oauth_signature')

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

class ReallyEqualMixin:
    def failUnlessReallyEqual(self, a, b, msg=None):
        self.failUnlessEqual(a, b, msg=msg)
        self.failUnlessEqual(type(a), type(b), msg="a :: %r, b :: %r, %r" % (a, b, msg))

class TestFuncs(unittest.TestCase):
    def test_to_unicode(self):
        self.failUnlessRaises(TypeError, oauth.to_unicode, '\xae')
        self.failUnlessRaises(TypeError, oauth.to_unicode_optional_iterator, '\xae')
        self.failUnlessRaises(TypeError, oauth.to_unicode_optional_iterator, ['\xae'])

        self.failUnlessEqual(oauth.to_unicode(':-)'), u':-)')
        self.failUnlessEqual(oauth.to_unicode(u'\u00ae'), u'\u00ae')
        self.failUnlessEqual(oauth.to_unicode('\xc2\xae'), u'\u00ae')
        self.failUnlessEqual(oauth.to_unicode_optional_iterator([':-)']), [u':-)'])
        self.failUnlessEqual(oauth.to_unicode_optional_iterator([u'\u00ae']), [u'\u00ae'])

class TestRequest(unittest.TestCase, ReallyEqualMixin):
    def test_setter(self):
        url = "http://example.com"
        method = "GET"
        req = oauth.Request(method)
        self.assertTrue(not hasattr(req, 'url') or req.url is None)
        self.assertTrue(not hasattr(req, 'normalized_url') or req.normalized_url is None)

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
        self.assertEquals(req.normalized_url, exp1)
        self.assertEquals(req.url, url1)

        req = oauth.Request(method, url2)
        self.assertEquals(req.normalized_url, exp2)
        self.assertEquals(req.url, url2)

    def test_bad_url(self):
        request = oauth.Request()
        try:
            request.url = "ftp://example.com"
            self.fail("Invalid URL scheme was accepted.")
        except ValueError:
            pass

    def test_unset_consumer_and_token(self):
        consumer = oauth.Consumer('my_consumer_key', 'my_consumer_secret')
        token = oauth.Token('my_key', 'my_secret')
        request = oauth.Request("GET", "http://example.com/fetch.php")
        request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer,
            token)

        self.assertEquals(consumer.key, request['oauth_consumer_key'])
        self.assertEquals(token.key, request['oauth_token'])

    def test_no_url_set(self):
        consumer = oauth.Consumer('my_consumer_key', 'my_consumer_secret')
        token = oauth.Token('my_key', 'my_secret')
        request = oauth.Request()

        try:
            try:
                request.sign_request(oauth.SignatureMethod_HMAC_SHA1(), 
                    consumer, token)
            except TypeError:
                self.fail("Signature method didn't check for a normalized URL.")
        except ValueError:
            pass

    def test_url_query(self):
        url = "https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-contacts=10"
        normalized_url = urlparse.urlunparse(urlparse.urlparse(url)[:3] + (None, None, None))
        method = "GET"
        
        req = oauth.Request(method, url)
        self.assertEquals(req.url, url)
        self.assertEquals(req.normalized_url, normalized_url)

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
            u'foo': u'baz',
            u'bar': u'foo',
            u'multi': [u'FOO',u'BAR'],
            u'uni_utf8': u'\xae',
            u'uni_unicode': u'\u00ae',
            u'uni_unicode_2': u'åÅøØ',
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

    def test_to_postdata_nonascii(self):
        realm = "http://sp.example.com/"

        params = {
            'nonasciithing': u'q\xbfu\xe9 ,aasp u?..a.s',
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'oauth_signature': "wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D",
        }

        req = oauth.Request("GET", realm, params)

        self.failUnlessReallyEqual(req.to_postdata(), 'nonasciithing=q%C2%BFu%C3%A9%20%2Caasp%20u%3F..a.s&oauth_nonce=4572616e48616d6d65724c61686176&oauth_timestamp=137131200&oauth_consumer_key=0685bd9184jfhq22&oauth_signature_method=HMAC-SHA1&oauth_version=1.0&oauth_token=ad180jjd733klru7&oauth_signature=wOJIO9A2W5mFwDgiDvZbTSMK%252FPY%253D')

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
    
    def test_to_url_with_query(self):
        url = "https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-contacts=10"

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
        # Note: the url above already has query parameters, so append new ones with &
        exp = urlparse.urlparse("%s&%s" % (url, urllib.urlencode(params)))
        res = urlparse.urlparse(req.to_url())
        self.assertEquals(exp.scheme, res.scheme)
        self.assertEquals(exp.netloc, res.netloc)
        self.assertEquals(exp.path, res.path)

        a = parse_qs(exp.query)
        b = parse_qs(res.query)
        self.assertTrue('alt' in b)
        self.assertTrue('max-contacts' in b)
        self.assertEquals(b['alt'], ['json'])
        self.assertEquals(b['max-contacts'], ['10'])
        self.assertEquals(a, b)

    def test_signature_base_string_nonascii_nonutf8(self):
        consumer = oauth.Consumer('consumer_token', 'consumer_secret')

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\u2766,+CA'
        req = oauth.Request("GET", url)
        self.failUnlessReallyEqual(req.normalized_url, u'http://api.simplegeo.com/1.0/places/address.json')
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'WhufgeZKyYpKsI70GZaiDaYwl6g=')

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc\xe2\x9d\xa6,+CA'
        req = oauth.Request("GET", url)
        self.failUnlessReallyEqual(req.normalized_url, u'http://api.simplegeo.com/1.0/places/address.json')
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'WhufgeZKyYpKsI70GZaiDaYwl6g=')

        url = 'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        req = oauth.Request("GET", url)
        self.failUnlessReallyEqual(req.normalized_url, u'http://api.simplegeo.com/1.0/places/address.json')
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'WhufgeZKyYpKsI70GZaiDaYwl6g=')

        url = u'http://api.simplegeo.com:80/1.0/places/address.json?q=monkeys&category=animal&address=41+Decatur+St,+San+Francisc%E2%9D%A6,+CA'
        req = oauth.Request("GET", url)
        self.failUnlessReallyEqual(req.normalized_url, u'http://api.simplegeo.com/1.0/places/address.json')
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), consumer, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'WhufgeZKyYpKsI70GZaiDaYwl6g=')

    def test_signature_base_string_with_query(self):
        url = "https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-contacts=10"
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
        self.assertEquals(req.normalized_url, 'https://www.google.com/m8/feeds/contacts/default/full/')
        self.assertEquals(req.url, 'https://www.google.com/m8/feeds/contacts/default/full/?alt=json&max-contacts=10')
        normalized_params = parse_qsl(req.get_normalized_parameters())
        self.assertTrue(len(normalized_params), len(params) + 2)
        normalized_params = dict(normalized_params)
        for key, value in params.iteritems():
            if key == 'oauth_signature':
                continue
            self.assertEquals(value, normalized_params[key])
        self.assertEquals(normalized_params['alt'], 'json')
        self.assertEquals(normalized_params['max-contacts'], '10')

    def test_get_normalized_parameters_empty(self):
        url = "http://sp.example.com/?empty="

        req = oauth.Request("GET", url)

        res = req.get_normalized_parameters()

        expected='empty='

        self.assertEquals(expected, res)

    def test_get_normalized_parameters_duplicate(self):
        url = "http://example.com/v2/search/videos?oauth_nonce=79815175&oauth_timestamp=1295397962&oauth_consumer_key=mykey&oauth_signature_method=HMAC-SHA1&q=car&oauth_version=1.0&offset=10&oauth_signature=spWLI%2FGQjid7sQVd5%2FarahRxzJg%3D"

        req = oauth.Request("GET", url)

        res = req.get_normalized_parameters()

        expected='oauth_consumer_key=mykey&oauth_nonce=79815175&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1295397962&oauth_version=1.0&offset=10&q=car'

        self.assertEquals(expected, res)

    def test_get_normalized_parameters_from_url(self):
        # example copied from
        # https://github.com/ciaranj/node-oauth/blob/master/tests/oauth.js
        # which in turns says that it was copied from
        # http://oauth.net/core/1.0/#sig_base_example .
        url = "http://photos.example.net/photos?file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original"

        req = oauth.Request("GET", url)

        res = req.get_normalized_parameters()

        expected = 'file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original'

        self.assertEquals(expected, res)

    def test_signing_base(self):
        # example copied from
        # https://github.com/ciaranj/node-oauth/blob/master/tests/oauth.js
        # which in turns says that it was copied from
        # http://oauth.net/core/1.0/#sig_base_example .
        url = "http://photos.example.net/photos?file=vacation.jpg&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_nonce=kllo9940pd9333jh&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1191242096&oauth_token=nnch734d00sl2jdk&oauth_version=1.0&size=original"

        req = oauth.Request("GET", url)

        sm = oauth.SignatureMethod_HMAC_SHA1()

        consumer = oauth.Consumer('dpf43f3p2l4k3l03', 'foo')
        key, raw = sm.signing_base(req, consumer, None)

        expected = 'GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal'
        self.assertEquals(expected, raw)

    def test_get_normalized_parameters(self):
        url = "http://sp.example.com/"

        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_consumer_key': "0685bd9184jfhq22",
            'oauth_signature_method': "HMAC-SHA1",
            'oauth_token': "ad180jjd733klru7",
            'multi': ['FOO','BAR', u'\u00ae', '\xc2\xae'],
            'multi_same': ['FOO','FOO'],
            'uni_utf8_bytes': '\xc2\xae',
            'uni_unicode_object': u'\u00ae'
        }

        req = oauth.Request("GET", url, params)

        res = req.get_normalized_parameters()

        expected='multi=BAR&multi=FOO&multi=%C2%AE&multi=%C2%AE&multi_same=FOO&multi_same=FOO&oauth_consumer_key=0685bd9184jfhq22&oauth_nonce=4572616e48616d6d65724c61686176&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131200&oauth_token=ad180jjd733klru7&oauth_version=1.0&uni_unicode_object=%C2%AE&uni_utf8_bytes=%C2%AE'

        self.assertEquals(expected, res)

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

    def test_set_signature_method(self):
        consumer = oauth.Consumer('key', 'secret')
        client = oauth.Client(consumer)

        class Blah:
            pass

        try:
            client.set_signature_method(Blah())
            self.fail("Client.set_signature_method() accepted invalid method.")
        except ValueError:
            pass

        m = oauth.SignatureMethod_HMAC_SHA1()
        client.set_signature_method(m)
        self.assertEquals(m, client.method)

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

    @mock.patch('oauth2.Request.make_timestamp')
    @mock.patch('oauth2.Request.make_nonce')
    def test_request_nonutf8_bytes(self, mock_make_nonce, mock_make_timestamp):
        mock_make_nonce.return_value = 5
        mock_make_timestamp.return_value = 6

        tok = oauth.Token(key="tok-test-key", secret="tok-test-secret")
        con = oauth.Consumer(key="con-test-key", secret="con-test-secret")
        params = {
            'oauth_version': "1.0",
            'oauth_nonce': "4572616e48616d6d65724c61686176",
            'oauth_timestamp': "137131200",
            'oauth_token': tok.key,
            'oauth_consumer_key': con.key
        }

        # If someone passes a sequence of bytes which is not ascii for
        # url, we'll raise an exception as early as possible.
        url = "http://sp.example.com/\x92" # It's actually cp1252-encoding...
        self.assertRaises(TypeError, oauth.Request, method="GET", url=url, parameters=params)

        # And if they pass an unicode, then we'll use it.
        url = u'http://sp.example.com/\u2019'
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'cMzvCkhvLL57+sTIxLITTHfkqZk=')

        # And if it is a utf-8-encoded-then-percent-encoded non-ascii
        # thing, we'll decode it and use it.
        url = "http://sp.example.com/%E2%80%99"
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'yMLKOyNKC/DkyhUOb8DLSvceEWE=')

        # Same thing with the params.
        url = "http://sp.example.com/"

        # If someone passes a sequence of bytes which is not ascii in
        # params, we'll raise an exception as early as possible.
        params['non_oauth_thing'] = '\xae', # It's actually cp1252-encoding...
        self.assertRaises(TypeError, oauth.Request, method="GET", url=url, parameters=params)

        # And if they pass a unicode, then we'll use it.
        params['non_oauth_thing'] = u'\u2019'
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_signature'], '0GU50m0v60CVDB5JnoBXnvvvKx4=')

        # And if it is a utf-8-encoded non-ascii thing, we'll decode
        # it and use it.
        params['non_oauth_thing'] = '\xc2\xae'
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_signature'], 'pqOCu4qvRTiGiXB8Z61Jsey0pMM=')


        # Also if there are non-utf8 bytes in the query args.
        url = "http://sp.example.com/?q=\x92" # cp1252
        self.assertRaises(TypeError, oauth.Request, method="GET", url=url, parameters=params)

    def test_request_hash_of_body(self):
        tok = oauth.Token(key="token", secret="tok-test-secret")
        con = oauth.Consumer(key="consumer", secret="con-test-secret")

        # Example 1a from Appendix A.1 of
        # http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
        # Except that we get a differetn result than they do.

        params = {
            'oauth_version': "1.0",
            'oauth_token': tok.key,
            'oauth_nonce': 10288510250934,
            'oauth_timestamp': 1236874155,
            'oauth_consumer_key': con.key
        }

        url = u"http://www.example.com/resource"
        req = oauth.Request(method="PUT", url=url, parameters=params, body="Hello World!", is_form_encoded=False)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_body_hash'], 'Lve95gjOVATpfV8EL5X4nxwjKHE=')
        self.failUnlessReallyEqual(req['oauth_signature'], 't+MX8l/0S8hdbVQL99nD0X1fPnM=')
        # oauth-bodyhash.html A.1 has
        # '08bUFF%2Fjmp59mWB7cSgCYBUpJ0U%3D', but I don't see how that
        # is possible.

        # Example 1b
        params = {
            'oauth_version': "1.0",
            'oauth_token': tok.key,
            'oauth_nonce': 10369470270925,
            'oauth_timestamp': 1236874236,
            'oauth_consumer_key': con.key
        }

        req = oauth.Request(method="PUT", url=url, parameters=params, body="Hello World!", is_form_encoded=False)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_body_hash'], 'Lve95gjOVATpfV8EL5X4nxwjKHE=')
        self.failUnlessReallyEqual(req['oauth_signature'], 'CTFmrqJIGT7NsWJ42OrujahTtTc=')

        # Appendix A.2
        params = {
            'oauth_version': "1.0",
            'oauth_token': tok.key,
            'oauth_nonce': 8628868109991,
            'oauth_timestamp': 1238395022,
            'oauth_consumer_key': con.key
        }

        req = oauth.Request(method="GET", url=url, parameters=params, is_form_encoded=False)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, None)
        self.failUnlessReallyEqual(req['oauth_body_hash'], '2jmj7l5rSw0yVb/vlWAYkK/YBwk=')
        self.failUnlessReallyEqual(req['oauth_signature'], 'Zhl++aWSP0O3/hYQ0CuBc7jv38I=')


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
            'DX01TdHws7OninCLK9VztNTH1M4=': oauth.SignatureMethod_HMAC_SHA1(),
            'con-test-secret&tok-test-secret': oauth.SignatureMethod_PLAINTEXT()
            }

        for exp, method in methods.items():
            req.sign_request(method, con, tok)
            self.assertEquals(req['oauth_signature_method'], method.name)
            self.assertEquals(req['oauth_signature'], exp)

        # Also if there are non-ascii chars in the URL.
        url = "http://sp.example.com/\xe2\x80\x99" # utf-8 bytes
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, tok)
        self.assertEquals(req['oauth_signature'], 'loFvp5xC7YbOgd9exIO6TxB7H4s=')

        url = u'http://sp.example.com/\u2019' # Python unicode object
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, tok)
        self.assertEquals(req['oauth_signature'], 'loFvp5xC7YbOgd9exIO6TxB7H4s=')

        # Also if there are non-ascii chars in the query args.
        url = "http://sp.example.com/?q=\xe2\x80\x99" # utf-8 bytes
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, tok)
        self.assertEquals(req['oauth_signature'], 'IBw5mfvoCsDjgpcsVKbyvsDqQaU=')

        url = u'http://sp.example.com/?q=\u2019' # Python unicode object
        req = oauth.Request(method="GET", url=url, parameters=params)
        req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), con, tok)
        self.assertEquals(req['oauth_signature'], 'IBw5mfvoCsDjgpcsVKbyvsDqQaU=')

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
        tok.set_verifier('this_is_a_test_verifier')
        con = oauth.Consumer(key="con-test-key", secret="con-test-secret")
        req = oauth.Request.from_consumer_and_token(con, token=tok,
            http_method="GET", http_url=url)

        self.assertEquals(req['oauth_token'], tok.key)
        self.assertEquals(req['oauth_consumer_key'], con.key)
        self.assertEquals(tok.verifier, req['oauth_verifier'])

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

    def test_build_authenticate_header(self):
        server = oauth.Server()
        headers = server.build_authenticate_header('example.com')
        self.assertTrue('WWW-Authenticate' in headers)
        self.assertEquals('OAuth realm="example.com"', 
            headers['WWW-Authenticate'])

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

        self.assertRaises(oauth.Error, server.verify_request, request, consumer, token)

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

    def create_simple_multipart_data(self, data):
        boundary = '---Boundary-%d' % random.randint(1,1000)
        crlf = '\r\n'
        items = []
        for key, value in data.iteritems():
            items += [
                '--'+boundary,
                'Content-Disposition: form-data; name="%s"'%str(key),
                '',
                str(value),
            ]
        items += ['', '--'+boundary+'--', '']
        content_type = 'multipart/form-data; boundary=%s' % boundary
        return content_type, crlf.join(items)

    def test_init(self):
        class Blah():
            pass

        try:
            client = oauth.Client(Blah())
            self.fail("Client.__init__() accepted invalid Consumer.")
        except ValueError:
            pass

        consumer = oauth.Consumer('token', 'secret')
        try:
            client = oauth.Client(consumer, Blah())
            self.fail("Client.__init__() accepted invalid Token.")
        except ValueError:
            pass

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

    @mock.patch('httplib2.Http.request')
    def test_multipart_post_does_not_alter_body(self, mockHttpRequest):
        random_result = random.randint(1,100)

        data = {
            'rand-%d'%random.randint(1,100):random.randint(1,100),
        }
        content_type, body = self.create_simple_multipart_data(data)

        client = oauth.Client(self.consumer, None)
        uri = self._uri('two_legged')

        def mockrequest(cl, ur, **kw):
            self.failUnless(cl is client)
            self.failUnless(ur is uri)
            self.failUnlessEqual(frozenset(kw.keys()), frozenset(['method', 'body', 'redirections', 'connection_type', 'headers']))
            self.failUnlessEqual(kw['body'], body)
            self.failUnlessEqual(kw['connection_type'], None)
            self.failUnlessEqual(kw['method'], 'POST')
            self.failUnlessEqual(kw['redirections'], httplib2.DEFAULT_MAX_REDIRECTS)
            self.failUnless(isinstance(kw['headers'], dict))

            return random_result

        mockHttpRequest.side_effect = mockrequest

        result = client.request(uri, 'POST', headers={'Content-Type':content_type}, body=body)
        self.assertEqual(result, random_result)

    @mock.patch('httplib2.Http.request')
    def test_url_with_query_string(self, mockHttpRequest):
        uri = 'http://example.com/foo/bar/?show=thundercats&character=snarf'
        client = oauth.Client(self.consumer, None)
        random_result = random.randint(1,100)

        def mockrequest(cl, ur, **kw):
            self.failUnless(cl is client)
            self.failUnlessEqual(frozenset(kw.keys()), frozenset(['method', 'body', 'redirections', 'connection_type', 'headers']))
            self.failUnlessEqual(kw['body'], '')
            self.failUnlessEqual(kw['connection_type'], None)
            self.failUnlessEqual(kw['method'], 'GET')
            self.failUnlessEqual(kw['redirections'], httplib2.DEFAULT_MAX_REDIRECTS)
            self.failUnless(isinstance(kw['headers'], dict))

            req = oauth.Request.from_consumer_and_token(self.consumer, None,
                    http_method='GET', http_url=uri, parameters={})
            req.sign_request(oauth.SignatureMethod_HMAC_SHA1(), self.consumer, None)
            expected = parse_qsl(urlparse.urlparse(req.to_url()).query)
            actual = parse_qsl(urlparse.urlparse(ur).query)
            self.failUnlessEqual(len(expected), len(actual))
            actual = dict(actual)
            for key, value in expected:
                if key not in ('oauth_signature', 'oauth_nonce', 'oauth_timestamp'):
                    self.failUnlessEqual(actual[key], value)

            return random_result

        mockHttpRequest.side_effect = mockrequest

        client.request(uri, 'GET')

    @mock.patch('httplib2.Http.request')
    @mock.patch('oauth2.Request.from_consumer_and_token')
    def test_multiple_values_for_a_key(self, mockReqConstructor, mockHttpRequest):
        client = oauth.Client(self.consumer, None)

        request = oauth.Request("GET", "http://example.com/fetch.php", parameters={'multi': ['1', '2']})
        mockReqConstructor.return_value = request

        client.request('http://whatever', 'POST', body='multi=1&multi=2')

        self.failUnlessEqual(mockReqConstructor.call_count, 1)
        self.failUnlessEqual(mockReqConstructor.call_args[1]['parameters'], {'multi': ['1', '2']})

        self.failUnless('multi=1' in mockHttpRequest.call_args[1]['body'])
        self.failUnless('multi=2' in mockHttpRequest.call_args[1]['body'])

if __name__ == "__main__":
    unittest.main()
