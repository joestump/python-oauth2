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

import base64
import urllib
import time
import random
import urlparse
import hmac
import binascii

try:
    from urlparse import parse_qs
    parse_qs # placate pyflakes
except ImportError:
    # fall back for Python 2.5
    from cgi import parse_qs

try:
    from hashlib import sha1
    sha = sha1
except ImportError:
    # hashlib was added in Python 2.5
    import sha

__version__ = '1.5-tweepy'

OAUTH_VERSION = '1.0'  # Hi Blaine!
HTTP_METHOD = 'GET'
SIGNATURE_METHOD = 'PLAINTEXT'


class Error(RuntimeError):
    """Generic exception class."""

    def __init__(self, message='OAuth error occurred.'):
        self._message = message

    @property
    def message(self):
        """A hack to get around the deprecation errors in 2.6."""
        return self._message

    def __str__(self):
        return self._message


class MissingSignature(Error):
    pass


def build_authenticate_header(realm=''):
    """Optional WWW-Authenticate header (401 error)"""
    return {'WWW-Authenticate': 'OAuth realm="%s"' % realm}


def build_xoauth_string(url, consumer, token=None):
    """Build an XOAUTH string for use in SMTP/IMPA authentication."""
    request = Request.from_consumer_and_token(consumer, token,
        "GET", url)

    signing_method = SignatureMethod_HMAC_SHA1()
    request.sign_request(signing_method, consumer, token)

    params = []
    for k, v in sorted(request.iteritems()):
        if v is not None:
            params.append('%s="%s"' % (k, escape(v)))

    return "%s %s %s" % ("GET", url, ','.join(params))


def to_unicode(s):
    """ Convert to unicode, raise exception with instructive error
    message if s is not unicode, ascii, or utf-8. """
    if not isinstance(s, unicode):
        if not isinstance(s, str):
            raise TypeError('You are required to pass either unicode or string here, not: %r (%s)' % (type(s), s))
        try:
            s = s.decode('utf-8')
        except UnicodeDecodeError, le:
            raise TypeError('You are required to pass either a unicode object or a utf-8 string here. You passed a Python string object which contained non-utf-8: %r. The UnicodeDecodeError that resulted from attempting to interpret it as utf-8 was: %s' % (s, le,))
    return s

def to_utf8(s):
    return to_unicode(s).encode('utf-8')

def to_unicode_if_string(s):
    if isinstance(s, basestring):
        return to_unicode(s)
    else:
        return s

def to_utf8_if_string(s):
    if isinstance(s, basestring):
        return to_utf8(s)
    else:
        return s

def to_unicode_optional_iterator(x):
    """
    Raise TypeError if x is a str containing non-utf8 bytes or if x is
    an iterable which contains such a str.
    """
    if isinstance(x, basestring):
        return to_unicode(x)

    try:
        l = list(x)
    except TypeError, e:
        assert 'is not iterable' in str(e)
        return x
    else:
        return [ to_unicode(e) for e in l ]

def to_utf8_optional_iterator(x):
    """
    Raise TypeError if x is a str or if x is an iterable which
    contains a str.
    """
    if isinstance(x, basestring):
        return to_utf8(x)

    try:
        l = list(x)
    except TypeError, e:
        assert 'is not iterable' in str(e)
        return x
    else:
        return [ to_utf8_if_string(e) for e in l ]

def escape(s):
    """Escape a URL including any /."""
    return urllib.quote(s.encode('utf-8'), safe='~')

def generate_timestamp():
    """Get seconds since epoch (UTC)."""
    return int(time.time())


def generate_nonce(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


def generate_verifier(length=8):
    """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])


class Consumer(object):
    """A consumer of OAuth-protected services.
 
    The OAuth consumer is a "third-party" service that wants to access
    protected resources from an OAuth service provider on behalf of an end
    user. It's kind of the OAuth client.
 
    Usually a consumer must be registered with the service provider by the
    developer of the consumer software. As part of that process, the service
    provider gives the consumer a *key* and a *secret* with which the consumer
    software can identify itself to the service. The consumer will include its
    key in each request to identify itself, but will use its secret only when
    signing requests, to prove that the request is from that particular
    registered consumer.
 
    Once registered, the consumer can then use its consumer credentials to ask
    the service provider for a request token, kicking off the OAuth
    authorization process.
    """

    key = None
    secret = None

    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

        if self.key is None or self.secret is None:
            raise ValueError("Key and secret must be set.")

    def __str__(self):
        data = {'oauth_consumer_key': self.key,
            'oauth_consumer_secret': self.secret}

        return urllib.urlencode(data)


class Token(object):
    """An OAuth credential used to request authorization or a protected
    resource.
 
    Tokens in OAuth comprise a *key* and a *secret*. The key is included in
    requests to identify the token being used, but the secret is used only in
    the signature, to prove that the requester is who the server gave the
    token to.
 
    When first negotiating the authorization, the consumer asks for a *request
    token* that the live user authorizes with the service provider. The
    consumer then exchanges the request token for an *access token* that can
    be used to access protected resources.
    """

    key = None
    secret = None
    callback = None
    callback_confirmed = None
    verifier = None

    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

        if self.key is None or self.secret is None:
            raise ValueError("Key and secret must be set.")

    def set_callback(self, callback):
        self.callback = callback
        self.callback_confirmed = 'true'

    def set_verifier(self, verifier=None):
        if verifier is not None:
            self.verifier = verifier
        else:
            self.verifier = generate_verifier()

    def get_callback_url(self):
        if self.callback and self.verifier:
            # Append the oauth_verifier.
            parts = urlparse.urlparse(self.callback)
            scheme, netloc, path, params, query, fragment = parts[:6]
            if query:
                query = '%s&oauth_verifier=%s' % (query, self.verifier)
            else:
                query = 'oauth_verifier=%s' % self.verifier
            return urlparse.urlunparse((scheme, netloc, path, params,
                query, fragment))
        return self.callback

    def to_string(self):
        """Returns this token as a plain string, suitable for storage.
 
        The resulting string includes the token's secret, so you should never
        send or store this string where a third party can read it.
        """

        data = {
            'oauth_token': self.key,
            'oauth_token_secret': self.secret,
        }

        if self.callback_confirmed is not None:
            data['oauth_callback_confirmed'] = self.callback_confirmed
        return urllib.urlencode(data)
 
    @staticmethod
    def from_string(s):
        """Deserializes a token from a string like one returned by
        `to_string()`."""

        if not len(s):
            raise ValueError("Invalid parameter string.")

        params = parse_qs(s, keep_blank_values=False)
        if not len(params):
            raise ValueError("Invalid parameter string.")

        try:
            key = params['oauth_token'][0]
        except Exception:
            raise ValueError("'oauth_token' not found in OAuth request.")

        try:
            secret = params['oauth_token_secret'][0]
        except Exception:
            raise ValueError("'oauth_token_secret' not found in " 
                "OAuth request.")

        token = Token(key, secret)
        try:
            token.callback_confirmed = params['oauth_callback_confirmed'][0]
        except KeyError:
            pass  # 1.0, no callback confirmed.
        return token

    def __str__(self):
        return self.to_string()


def setter(attr):
    name = attr.__name__
 
    def getter(self):
        try:
            return self.__dict__[name]
        except KeyError:
            raise AttributeError(name)
 
    def deleter(self):
        del self.__dict__[name]
 
    return property(getter, attr, deleter)


class Request(dict):
 
    """The parameters and information for an HTTP request, suitable for
    authorizing with OAuth credentials.
 
    When a consumer wants to access a service's protected resources, it does
    so using a signed HTTP request identifying itself (the consumer) with its
    key, and providing an access token authorized by the end user to access
    those resources.
 
    """
 
    version = OAUTH_VERSION

    def __init__(self, method=HTTP_METHOD, url=None, parameters=None,
                 body='', is_form_encoded=False):
        if url is not None:
            self.url = to_unicode(url)
        self.method = method
        if parameters is not None:
            for k, v in parameters.iteritems():
                k = to_unicode(k)
                v = to_unicode_optional_iterator(v)
                self[k] = v
        self.body = body
        self.is_form_encoded = is_form_encoded


    @setter
    def url(self, value):
        self.__dict__['url'] = value
        if value is not None:
            scheme, netloc, path, params, query, fragment = urlparse.urlparse(value)

            # Exclude default port numbers.
            if scheme == 'http' and netloc[-3:] == ':80':
                netloc = netloc[:-3]
            elif scheme == 'https' and netloc[-4:] == ':443':
                netloc = netloc[:-4]
            if scheme not in ('http', 'https'):
                raise ValueError("Unsupported URL %s (%s)." % (value, scheme))

            # Normalized URL excludes params, query, and fragment.
            self.normalized_url = urlparse.urlunparse((scheme, netloc, path, None, None, None))
        else:
            self.normalized_url = None
            self.__dict__['url'] = None
 
    @setter
    def method(self, value):
        self.__dict__['method'] = value.upper()
 
    def _get_timestamp_nonce(self):
        return self['oauth_timestamp'], self['oauth_nonce']
 
    def get_nonoauth_parameters(self):
        """Get any non-OAuth parameters."""
        return dict([(k, v) for k, v in self.iteritems() 
                    if not k.startswith('oauth_')])
 
    def to_header(self, realm=''):
        """Serialize as a header for an HTTPAuth request."""
        oauth_params = ((k, v) for k, v in self.items() 
                            if k.startswith('oauth_'))
        stringy_params = ((k, escape(str(v))) for k, v in oauth_params)
        header_params = ('%s="%s"' % (k, v) for k, v in stringy_params)
        params_header = ', '.join(header_params)
 
        auth_header = 'OAuth realm="%s"' % realm
        if params_header:
            auth_header = "%s, %s" % (auth_header, params_header)
 
        return {'Authorization': auth_header}
 
    def to_postdata(self):
        """Serialize as post data for a POST request."""
        d = {}
        for k, v in self.iteritems():
            d[k.encode('utf-8')] = to_utf8_optional_iterator(v)

        # tell urlencode to deal with sequence values and map them correctly
        # to resulting querystring. for example self["k"] = ["v1", "v2"] will
        # result in 'k=v1&k=v2' and not k=%5B%27v1%27%2C+%27v2%27%5D
        return urllib.urlencode(d, True).replace('+', '%20')
 
    def to_url(self):
        """Serialize as a URL for a GET request."""
        base_url = urlparse.urlparse(self.url)
        try:
            query = base_url.query
        except AttributeError:
            # must be python <2.5
            query = base_url[4]
        query = parse_qs(query)
        for k, v in self.items():
            query.setdefault(k, []).append(v)
        
        try:
            scheme = base_url.scheme
            netloc = base_url.netloc
            path = base_url.path
            params = base_url.params
            fragment = base_url.fragment
        except AttributeError:
            # must be python <2.5
            scheme = base_url[0]
            netloc = base_url[1]
            path = base_url[2]
            params = base_url[3]
            fragment = base_url[5]
        
        url = (scheme, netloc, path, params,
               urllib.urlencode(query, True), fragment)
        return urlparse.urlunparse(url)

    def get_parameter(self, parameter):
        ret = self.get(parameter)
        if ret is None:
            raise Error('Parameter not found: %s' % parameter)

        return ret

    def get_normalized_parameters(self):
        """Return a string that contains the parameters that must be signed."""
        items = []
        for key, value in self.iteritems():
            if key == 'oauth_signature':
                continue
            # 1.0a/9.1.1 states that kvp must be sorted by key, then by value,
            # so we unpack sequence values into multiple items for sorting.
            if isinstance(value, basestring):
                items.append((to_utf8_if_string(key), to_utf8(value)))
            else:
                try:
                    value = list(value)
                except TypeError, e:
                    assert 'is not iterable' in str(e)
                    items.append((to_utf8_if_string(key), to_utf8_if_string(value)))
                else:
                    items.extend((to_utf8_if_string(key), to_utf8_if_string(item)) for item in value)

        # Include any query string parameters from the provided URL
        query = urlparse.urlparse(self.url)[4]

        url_items = self._split_url_string(query).items()
        url_items = [(to_utf8(k), to_utf8(v)) for k, v in url_items if k != 'oauth_signature' ]
        items.extend(url_items)

        items.sort()
        encoded_str = urllib.urlencode(items)
        # Encode signature parameters per Oauth Core 1.0 protocol
        # spec draft 7, section 3.6
        # (http://tools.ietf.org/html/draft-hammer-oauth-07#section-3.6)
        # Spaces must be encoded with "%20" instead of "+"
        return encoded_str.replace('+', '%20').replace('%7E', '~')

    def sign_request(self, signature_method, consumer, token):
        """Set the signature parameter to the result of sign."""

        if not self.is_form_encoded:
            # according to
            # http://oauth.googlecode.com/svn/spec/ext/body_hash/1.0/oauth-bodyhash.html
            # section 4.1.1 "OAuth Consumers MUST NOT include an
            # oauth_body_hash parameter on requests with form-encoded
            # request bodies."
            self['oauth_body_hash'] = base64.b64encode(sha(self.body).digest())

        if 'oauth_consumer_key' not in self:
            self['oauth_consumer_key'] = consumer.key

        if token and 'oauth_token' not in self:
            self['oauth_token'] = token.key

        self['oauth_signature_method'] = signature_method.name
        self['oauth_signature'] = signature_method.sign(self, consumer, token)
 
    @classmethod
    def make_timestamp(cls):
        """Get seconds since epoch (UTC)."""
        return str(int(time.time()))
 
    @classmethod
    def make_nonce(cls):
        """Generate pseudorandom number."""
        return str(random.randint(0, 100000000))
 
    @classmethod
    def from_request(cls, http_method, http_url, headers=None, parameters=None,
            query_string=None):
        """Combines multiple parameter sources."""
        if parameters is None:
            parameters = {}
 
        # Headers
        if headers and 'Authorization' in headers:
            auth_header = headers['Authorization']
            # Check that the authorization header is OAuth.
            if auth_header[:6] == 'OAuth ':
                auth_header = auth_header[6:]
                try:
                    # Get the parameters from the header.
                    header_params = cls._split_header(auth_header)
                    parameters.update(header_params)
                except:
                    raise Error('Unable to parse OAuth parameters from '
                        'Authorization header.')
 
        # GET or POST query string.
        if query_string:
            query_params = cls._split_url_string(query_string)
            parameters.update(query_params)
 
        # URL parameters.
        param_str = urlparse.urlparse(http_url)[4] # query
        url_params = cls._split_url_string(param_str)
        parameters.update(url_params)
 
        if parameters:
            return cls(http_method, http_url, parameters)
 
        return None
 
    @classmethod
    def from_consumer_and_token(cls, consumer, token=None,
            http_method=HTTP_METHOD, http_url=None, parameters=None,
            body='', is_form_encoded=False):
        if not parameters:
            parameters = {}
 
        defaults = {
            'oauth_consumer_key': consumer.key,
            'oauth_timestamp': cls.make_timestamp(),
            'oauth_nonce': cls.make_nonce(),
            'oauth_version': cls.version,
        }
 
        defaults.update(parameters)
        parameters = defaults
 
        if token:
            parameters['oauth_token'] = token.key
            if token.verifier:
                parameters['oauth_verifier'] = token.verifier
 
        return Request(http_method, http_url, parameters, body=body, 
                       is_form_encoded=is_form_encoded)
 
    @classmethod
    def from_token_and_callback(cls, token, callback=None, 
        http_method=HTTP_METHOD, http_url=None, parameters=None):

        if not parameters:
            parameters = {}
 
        parameters['oauth_token'] = token.key
 
        if callback:
            parameters['oauth_callback'] = callback
 
        return cls(http_method, http_url, parameters)
 
    @staticmethod
    def _split_header(header):
        """Turn Authorization: header into parameters."""
        params = {}
        parts = header.split(',')
        for param in parts:
            # Ignore realm parameter.
            if param.find('realm') > -1:
                continue
            # Remove whitespace.
            param = param.strip()
            # Split key-value.
            param_parts = param.split('=', 1)
            # Remove quotes and unescape the value.
            params[param_parts[0]] = urllib.unquote(param_parts[1].strip('\"'))
        return params
 
    @staticmethod
    def _split_url_string(param_str):
        """Turn URL string into parameters."""
        parameters = parse_qs(param_str.encode('utf-8'), keep_blank_values=True)
        for k, v in parameters.iteritems():
            parameters[k] = urllib.unquote(v[0])
        return parameters


class SignatureMethod(object):
    """A way of signing requests.
 
    The OAuth protocol lets consumers and service providers pick a way to sign
    requests. This interface shows the methods expected by the other `oauth`
    modules for signing requests. Subclass it and implement its methods to
    provide a new way to sign requests.
    """

    def signing_base(self, request, consumer, token):
        """Calculates the string that needs to be signed.

        This method returns a 2-tuple containing the starting key for the
        signing and the message to be signed. The latter may be used in error
        messages to help clients debug their software.

        """
        raise NotImplementedError

    def sign(self, request, consumer, token):
        """Returns the signature for the given request, based on the consumer
        and token also provided.

        You should use your implementation of `signing_base()` to build the
        message to sign. Otherwise it may be less useful for debugging.

        """
        raise NotImplementedError

    def check(self, request, consumer, token, signature):
        """Returns whether the given signature is the correct signature for
        the given consumer and token signing the given request."""
        built = self.sign(request, consumer, token)
        return built == signature


class SignatureMethod_HMAC_SHA1(SignatureMethod):
    name = 'HMAC-SHA1'

    def signing_base(self, request, consumer, token):
        if not hasattr(request, 'normalized_url') or request.normalized_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            escape(request.method),
            escape(request.normalized_url),
            escape(request.get_normalized_parameters()),
        )

        key = '%s&' % escape(consumer.secret)
        if token:
            key += escape(token.secret)
        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(request, consumer, token)

        hashed = hmac.new(key, raw, sha)

        # Calculate the digest base 64.
        return binascii.b2a_base64(hashed.digest())[:-1]


class SignatureMethod_PLAINTEXT(SignatureMethod):

    name = 'PLAINTEXT'

    def signing_base(self, request, consumer, token):
        """Concatenates the consumer key and secret with the token's
        secret."""
        sig = '%s&' % escape(consumer.secret)
        if token:
            sig = sig + escape(token.secret)
        return sig, sig

    def sign(self, request, consumer, token):
        key, raw = self.signing_base(request, consumer, token)
        return raw
