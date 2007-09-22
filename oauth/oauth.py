import urllib
import random
import time

OAUTH_VERSION = '1.0'

DEFAULT_REQUEST_METHOD = 'GET'

# Signature methods supported by this library so far
SIGNATURE_METHOD_HMAC_SHA1 = 'HMAC-SHA1'
SIGNATURE_METHOD_PLAINTEXT = 'PLAINTEXT'

DEFAULT_SIGNATURE_METHOD = SIGNATURE_METHOD_HMAC_SHA1

class OAuthError(RuntimeError):
    # Any OAuth-related error condition
    def __init__(self, message='OAuth error occured'):
        self.message = message
        
class OAuthToken():
    # A token object, mostly for testing
    def __init__(self, token, secret, token_type='request'):
        self.token = token
        self.secret = secret
        self.token_type = token_type
        
    def __str__(self):
        return 'oauth_token=%s&oauth_token_secret=%s' % (self.token, self.secret)
        
# Base class for OAuthConsumer and OAuthServiceProvider
class OAuth():
    oauth_version = OAUTH_VERSION

    def generate_nonce(self, length=8):
        # pseudorandom number
        return ''.join(str(random.randint(0, 9)) for i in range(length))
    
    def is_valid_nonce(self, nonce, recently_used_nonces):
        # check that this nonce is not in the list of used numbers.
        # list contents are determined by the service provider.
        return not nonce in recently_used_nonces

    def generate_timestamp(self):
        # seconds since epoch (UTC)
        return int(time.time())
    
    def is_valid_timestamp(self, ts, last_timestamp):
        # Check that the current timestamp is sequentially greater than the last timestamp
        # if the last timestamp is specified.
        if last_timestamp:
            return ts > last_timestamp
        return True
    
    def generate_random_string(self, chars=None, length=16):
        # generate a random string
        # could be used for oauth_token and/or oauth_token_secret
        if chars is None:
            chars = self.DEFAULT_CHARS
        return ''.join(chars[random.randrange(len(chars))] for i in range(length))
    
    def get_endpoint_url(self, request_url):
        try:
            # find everything before the params
            return request_url[:request_url.index('?')]
        except:
            return request_url
        
    def escape(self, s):
        # escape '/' too
        return urllib.quote(s, safe='')
    
    def normalize_request_parameters(self, request_params):
        '''
        Sorts the dictionary of request parameters alphabetically by key
        and combines the RFC3986 percent-encoded key, value pair as a string.
        
        >>> oauth = OAuth()
        >>> params = {'page': 3, 'count': 50, 'friends': 18, 'type': 'link', 'message': 'hello world'}
        >>> oauth.normalize_request_parameters(params)
        'count%3D50%26friends%3D18%26message%3Dhello%20world%26page%3D3%26type%3Dlink'
        '''
        keys = request_params.keys()
        # sort alphabetically
        keys.sort()
        # combine key value pairs in string and escape
        normalized = self.escape('&'.join('%s=%s' % (str(k), request_params[k]) for k in keys))
        return normalized
    
    def concatinate_request_parameters(self, consumer_secret,
        endpoint_url='', normalized_request_parameters='',
        http_request_method=DEFAULT_REQUEST_METHOD, token_secret=''):
        '''
        The following items MUST be concatenated in order into a single string. Each item is separated by an '&' character (ASCII code 38), even if empty.

           1. The URL as defined in "Endpoint URLs" excluding the query and fragment parts.
           2. The normalized request parameters string from step 1.
           3. The HTTP request method used to send the request. Value MUST be uppercase, for example: HEAD, GET, POST, etc.
           4. The Consumer Secret, encoded per "Parameter Encoding".
           5. The Token Secret, encoded per "Parameter Encoding" (empty value if oauth_token is not present).
        
        >>> oauth = OAuth()
        >>> endpoint_url = 'http://photos.example.net/photos'
        >>> normalized_request_parameters = 'file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26size%3Doriginal'
        >>> token_secret = 'pfkkdhi9sl3r4s00'
        >>> oauth.concatinate_request_parameters('kd94hf93k423kf44', endpoint_url=endpoint_url, normalized_request_parameters=normalized_request_parameters, http_request_method='GET', token_secret=token_secret)
        'http://photos.example.net/photos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26size%3Doriginal&GET&kd94hf93k423kf44&pfkkdhi9sl3r4s00'
        '''
        return '&'.join((endpoint_url, normalized_request_parameters, http_request_method, consumer_secret, token_secret))
    
    def sign_request(self, signature_method, consumer_secret,
        token_secret='', endpoint_url='', request_parameters={},
        http_request_method=DEFAULT_REQUEST_METHOD):
        '''
        The purpose of signing API requests is to prevent unauthorized parties
        from using the Consumer Key and Tokens when making OAuth Endpoint URL requests or API Endpoint URL requests.
        The signature process encodes the Consumer Secret and Token Secret into a verifiable value which is included with the request.
        
        The process of generating the Signature Base String is as follows:
        
            1. Normalize request parameters
            2. Concatenate request elements
        
        Next, sign the base string using the signature method specified.
        Right now possible values for oauth_signature_method are 'PLAINTEXT' and 'HMAC-SHA1'.
        More signature methods coming soon...
        
        >>> oauth = OAuth()
        >>> consumer_secret = 'kd94hf93k423kf44'
        >>> token_secret = 'pfkkdhi9sl3r4s00'
        >>> endpoint_url = 'http://photos.example.net/photos'
        >>> ts = 1191242096
        >>> nonce = 'kllo9940pd9333jh'
        
        >>> signature_method = 'PLAINTEXT'
        >>> request_parameters = {'file': 'vacation.jpg', 'size': 'original', 'oauth_consumer_key': 'dpf43f3p2l4k3l03', 'oauth_token': 'nnch734d00sl2jdk', 'oauth_signature_method': signature_method, 'oauth_timestamp': ts, 'oauth_nonce': nonce}
        >>> oauth.sign_request(signature_method, consumer_secret, token_secret=token_secret)
        'kd94hf93k423kf44.pfkkdhi9sl3r4s00'
        
        >>> signature_method = 'HMAC-SHA1'
        >>> request_parameters = {'file': 'vacation.jpg', 'size': 'original', 'oauth_consumer_key': 'dpf43f3p2l4k3l03', 'oauth_token': 'nnch734d00sl2jdk', 'oauth_signature_method': signature_method, 'oauth_timestamp': ts, 'oauth_nonce': nonce}
        >>> oauth.sign_request(signature_method, consumer_secret, token_secret=token_secret, endpoint_url=endpoint_url, request_parameters=request_parameters)
        '3a4df91bba14e81cde073c9070beec993e45a2d6'
        
        '''
        # Sign the request based on signature method
        if signature_method == SIGNATURE_METHOD_PLAINTEXT:
            # should be used over a secure channel such as HTTPS
            return '.'.join((self.escape(consumer_secret), self.escape(token_secret)))
        else:
            # Normalize request parameters
            normalized_request_parameters = self.normalize_request_parameters(request_parameters)
            
            # Concatinate request elements
            signature_base_string = self.concatinate_request_parameters(
                consumer_secret,
                endpoint_url,
                normalized_request_parameters,
                http_request_method,
                token_secret)
            
            # Create the key
            key = '&'.join((self.escape(consumer_secret), self.escape(token_secret)))
            
            import hmac
            import hashlib
            
            if signature_method == SIGNATURE_METHOD_HMAC_SHA1:
                # use hmac with sha1
                h = hmac.new(key, signature_base_string, hashlib.sha1)
            else:
                raise OAuthError('Invalid signing algorithm')
            
            # calculate the digest in hex string format 
            return h.hexdigest()

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()