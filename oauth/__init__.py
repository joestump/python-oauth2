import cgi
import urllib
import time
import random

VERSION = '1.0' # Hi Blaine!
HTTP_METHOD = 'GET'
SIGNATURE_METHOD = 'PLAINTEXT'

# Generic exception class
class OAuthError(RuntimeError):
    def __init__(self, message='OAuth error occured'):
        self.message = message

# OAuthConsumer is a data type that represents the identity of the Consumer
# via its shared secret with the Service Provider.
class OAuthConsumer(object):
    key = None
    secret = None
    
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

# OAuthToken is a data type that represents an End User via either an access
# or request token.     
class OAuthToken(object):
    # access tokens and request tokens
    key = None
    secret = None
    
    '''
    key = the token
    secret = the token secret
    '''
    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def to_string(self):
        return urllib.urlencode({'oauth_token': self.key, 'oauth_token_secret': self.secret})
    
    # return a token from something like:
    # oauth_token_secret=digg&oauth_token=digg
    @staticmethod   
    def from_string(s):
        params = cgi.parse_qs(s, keep_blank_values=False)
        key = params['oauth_token'][0]
        secret = params['oauth_token_secret'][0]
        return OAuthToken(key, secret)
        
    def __str__(self):
        return self.to_string()
        
# OAuthRequest represents the request and can be serialized
class OAuthRequest(object):
    '''
    OAuth parameters:
        - oauth_consumer_key 
        - oauth_token
        - oauth_signature_method
        - oauth_signature 
        - oauth_timestamp 
        - oauth_nonce
        - oauth_version
        ... any additional parameters, as defined by the Service Provider.
    '''
    parameters = {} # oauth parameters
    http_method = HTTP_METHOD
    http_url = None
    version = VERSION

    def __init__(self, http_method=HTTP_METHOD, http_url=None, parameters={}):
        self.http_method = http_method
        self.http_url = http_url
        self.parameters = parameters
    
    def escape(self, s):
        # escape '/' too
        return urllib.quote(s, safe='')
    
    def set_parameter(self, parameter, value):
        self.parameters[parameter] = value
    
    def get_parameter(self, parameter):
        try:
            return self.parameters[parameter]
        except:
            raise OAuthError
    
    def get_timestamp_nonce(self):
        return self.get_parameter('oauth_timestamp'), self.get_parameter('oauth_nonce')
    
    # serialize as a header for an HTTPAuth request
    def to_header(self, realm=''):
        auth_header = 'OAuth realm="%s"' % realm
        # add the oauth parameters
        if self.parameters:
            for k, v in self.parameters.iteritems():
                auth_header += ',\n\t %s="%s"' % (k, v)
        return {'Authorization': auth_header}
    
    # serialize as post data for a POST request
    def to_postdata(self):
        pass
    
    # serialize as a url for a GET request
    def to_url(self):
        pass
    
    def normalize_request_parameters(self):
        pass
    
    # set the signature parameter to the result of build_signature
    def sign_request(self, signature_method, consumer, token):
        # set the signature method
        self.set_parameter('oauth_signature_method', signature_method.get_name())
        # set the signature
        self.set_parameter('oauth_signature', self.build_signature(signature_method, consumer, token))
    
    def build_signature(self, signature_method, consumer, token):
        # call the build signature method within the signature method
        return signature_method.build_signature(self, consumer, token)
    
    @staticmethod
    def from_request(http_method, http_url, headers, parameters=None):
        # Hi Andy! What's the equivalent to php $_SERVER for Python?
        # Is the php version of this method flexible enough?
        # If the params exist, why wouldn't the sp just call the constructor?

        try:
            auth_header = headers['Authorization']
            # check that the authorization header is OAuth
            auth_header.index('OAuth')
            # get the parameters from the header
            parameters = OAuthRequest._split_header(auth_header)
            return OAuthRequest(http_method, http_url, parameters)
        except:
            pass
        
    @staticmethod
    def from_consumer_and_token(oauth_consumer, token=None, http_method=HTTP_METHOD, http_url=None, parameters=None):
        if not parameters:
            parameters = {}
        
        defaults = {
            'oauth_consumer_key': oauth_consumer.key,
            'oauth_timestamp': OAuthRequest._generate_timestamp(),
            'oauth_nonce': OAuthRequest._generate_nonce(),
            'oauth_version': OAuthRequest.version,
        }
        
        defaults.update(parameters)
        parameters = defaults
        
        if token:
            parameters['token'] = token.key
        
        return OAuthRequest(http_method, http_url, parameters)
    
    # util function: current timestamp
    # seconds since epoch (UTC)
    @staticmethod
    def _generate_timestamp():
        return int(time.time())
    
    # util function: nonce
    # pseudorandom number
    @staticmethod
    def _generate_nonce(length=8):
        return ''.join(str(random.randint(0, 9)) for i in range(length))
    
    # util function: turn Authorization: header into parameters, has to do some unescaping
    @staticmethod
    def _split_header(header):
        params = {}
        parts = header.split(',')
        for param in parts:
            # ignore non-oauth parameters
            if param.find('oauth_') < 0:
                continue
            # remove whitespace
            param = param.strip()
            # split key-value
            param_parts = param.split('=')
            # remove quotes and unescape the value
            params[param_parts[0]] = urllib.unquote_plus(param_parts[1].strip('\"'))
        return params

# OAuthServer is a worker to check a requests validity against a data store
class OAuthServer(object):
    timestamp_threshold = 300 # in seconds, five minutes
    version = VERSION
    signature_methods = {}
    data_store = None
    
    def __init__(self, data_store=None):
        self.data_store = data_store
        
    def set_data_store(self, oauth_data_store):
        self.data_store = data_store
    
    def get_data_store(self):
        return self.data_store
    
    def add_signature_method(self, signature_method):
        self.signature_methods[signature_method.get_name()] = signature_method
        return self.signature_methods
    
    # process a request_token request
    # returns the request token on success
    def fetch_request_token(self, oauth_request):
        version = self._get_version(oauth_request)
        consumer = self._get_consumer(oauth_request)
        # no token required for the initial token request
        token = None
        self._check_signature(oauth_request, consumer, token)
        new_token = self.data_store.fetch_request_token(consumer)
        return new_token
    
    def fetch_access_token(self, oauth_request):
        # -> OAuthToken
        raise NotImplementedError
    
    def verify_request(self, oauth_request):
        # -> OAuthToken
        pass
        
    def _get_version(self, oauth_request):
        
        version = oauth_request.get_parameter('oauth_version')
        if not version:
            version = VERSION
        if version and version != self.version:
            raise OAuthError('OAuth version %s not supported' % str(version))
        return version
        
    # figure out the signature with some defaults
    def _get_signature_method(self, oauth_request):
        try:
            signature_method = oauth_request.get_parameter('oauth_signature_method')
        except:
            signature_method = SIGNATURE_METHOD
        try:
            # get the signature method object
            signature_method = self.signature_methods[signature_method]
        except:
            signature_method_names = ', '.join(self.signature_methods.keys())
            raise OAuthError('Signature method %s not supported try one of the following: %s' % (signature_method, signature_method_names))
        
        return signature_method
    
    def _get_consumer(self, oauth_request):
        consumer_key = oauth_request.get_parameter('oauth_consumer_key')
        if not consumer_key:
            raise OAuthError('Invalid consumer key')
        consumer = self.data_store.lookup_consumer(consumer_key)
        if not consumer:
            raise OAuthError('Invalid consumer')
        return consumer
        
    def _check_signature(self, oauth_request, consumer, token):
        timestamp, nonce = oauth_request.get_timestamp_nonce()
        self._check_timestamp(timestamp)
        self._check_nonce(consumer, token, nonce)
        signature_method = self._get_signature_method(oauth_request)
        try:
            signature = oauth_request.get_parameter('oauth_signature')
        except:
            raise OAuthError('Missing signature')
        # attempt to construct the same signature
        built = signature_method.build_signature(oauth_request, consumer, token)
        if signature != built:
            raise OAuthError('Invalid signature')
    
    def _check_timestamp(self, timestamp):
        # verify that timestamp is recentish
        timestamp = int(timestamp)
        now = int(time.time())
        lapsed = now - timestamp
        if lapsed > self.timestamp_threshold:
            raise OAuthError('Expired timestamp: given %d and now %s has a greater difference than threshold %d' % (timestamp, now, self.timestamp_threshold))
    
    def _check_nonce(self, consumer, token, nonce):
        # verify that the nonce is uniqueish
        try:
            self.data_store.lookup_nonce(consumer, token, nonce)
            raise OAuthError('Nonce already used: %s' % str(nonce))
        except:
            pass

# OAuthClient is a worker to attempt to execute a request
class OAuthClient(object):
    consumer = None
    token = None
    
    def __init__(self, oauth_consumer, oauth_token):
        self.consumer = oauth_consumer
        self.token = oauth_token
    
    def get_consumer(self):
        return self.consumer
    
    def get_token(self):
        return self.token
    
    def fetch_request_token(self, oauth_request):
        # -> OAuthToken
        raise NotImplementedError
    
    def fetch_access_token(self, oauth_request):
        # -> OAuthToken
        raise NotImplementedError

# OAuthDataStore is a database abstraction used to lookup consumers and tokens
class OAuthDataStore(object):
    
    def lookup_consumer(self, key):
        # -> OAuthConsumer
        raise NotImplementedError
    
    def lookup_token(self, oauth_consumer, token_type, token_token):
        # -> OAuthToken
        raise NotImplementedError
    
    def lookup_nonce(self, oauth_consumer, oauth_token, nonce, timestamp):
        # -> OAuthToken
        raise NotImplementedError
    
    def fetch_request_token(self, oauth_consumer):
        # -> OAuthToken
        raise NotImplementedError
    
    def fetch_access_token(self, oauth_consumer, oauth_token):
        # -> OAuthToken
        raise NotImplementedError

# OAuthSignatureMethod is a strategy class that implements a signature method
class OAuthSignatureMethod(object):
    def get_name():
        # -> str
        raise NotImplementedError
        
    def build_signature(oauth_request, oauth_consumer, oauth_token):
        # -> str
        raise NotImplementedError
        
class OAuthSignatureMethod_HMAC_SHA1(OAuthSignatureMethod):

    def get_name(self):
        return 'HMAC-SHA1'
        
    def build_signature(self, oauth_request, consumer, token):
        pass
        

'''
    
    $sig = array(
      urlencode($request->get_normalized_http_method()),
      urlencode($request->get_normalized_http_url()),
      urlencode($request->get_signable_parameters()),
    );

    $key = $consumer->secret . "&";

    if ($token) {
      $key .= $token->secret;
    }

    $raw = implode("&", $sig);
    //$this->base_string = $raw;

    // this is silly.
    $hashed = base64_encode(hash_hmac("sha1", $raw, $key, TRUE));
    return $hashed;
  }/*}}}*/
}/*}}}*/
'''

class OAuthSignatureMethod_PLAINTEXT(OAuthSignatureMethod):
    
    def get_name(self):
        return 'PLAINTEXT'
    
    def build_signature(self, oauth_request, consumer, token):
    
        # concatenate the consumer key and secret
        sig = oauth_request.escape(consumer.secret)
        
        if token:
            sig = '&'.join(key, oauth_request.escape(token.secret))
        
        return sig