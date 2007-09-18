import urllib
import random
import time

DEFAULT_REQUEST_METHOD = 'GET'
DEFAULT_SIGALG = 'sha1'

class OAuthError(RuntimeError):
    # Any OAuth-related error condition
    def __init__(self, message='OAuth error occured'):
        self.message = message
        
class OAuthToken():
    # A token object, mostly for testing
    def __init__(self, token, secret, token_type='single-use'):
        self.token = token
        self.secret = secret
        self.token_type = token_type
        
# Base class for OAuthConsumer and OAuthServiceProvider
class OAuth():

    DEFAULT_ACCEPTABLE_TS_DELAY = 300 # in seconds, five minutes

    def generate_nonce(self, length=8):
        # pseudorandom number
        return ''.join(str(random.randint(0, 9)) for i in range(length))
    
    def is_valid_nonce(self, nonce, used_nonces):
        # check that this nonce is not in the list of used numbers.
        # list contents are determined by the service provider.
        return not nonce in used_nonces

    def generate_timestamp(self):
        # seconds since epoch (UTC)
        return int(time.time())
    
    def is_valid_timestamp(self, ts, acceptable_delay=DEFAULT_ACCEPTABLE_TS_DELAY):
        # check that the current timestamp as determined by the service provider
        # is close enough to the timestamp provided by the consumer
        # (within the acceptable delay).
        return 0 <= self.generate_timestamp() - int(ts) <= acceptable_delay  
    
    def generate_random_string(self, chars=None, length=16):
        # generate a random string
        # could be used for oauth_token and/or oauth_token_secret
        if chars is None:
            chars = self.DEFAULT_CHARS
        return ''.join(chars[random.randrange(len(chars))] for i in range(length))
    
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
        # combine escaped key value pairs in string
        normalized = ''.join('&%s=%s' % (str(k), request_params[k]) for k in keys)[1:] # remove the first ampersand
        return urllib.quote(normalized)
    
    def get_http_request_uri(self, request_url):
        try:
            # find everything before the params
            return request_url[:request_url.index('?')]
        except:
            return request_url
        
    def escape_http_request_uri(self, http_request_uri):
        # escape '/' too
        return urllib.quote(http_request_uri, safe='')

    def sign_request(self, consumer_secret, consumer_key, oauth_sigalg=DEFAULT_SIGALG, **kwargs):
        '''
        Sorts the parameters according to OAuth spec and
        signs the string using the provided signing algorithm (oauth_sigalg).
        
        Possible values for oauth_sigalg are 'md5', 'sha1', and 'hmac'.
        These are the ones included in standard Python modules and I'm pretty lazy.
        More are available here: http://www.amk.ca/python/code/crypto.html
        
        Order of request parameters for signing:
        
        1. oauth_consumer_secret *: The Consumer Secret.
        2. oauth_consumer_key *: The Consumer Key.
        3. oauth_token : The Single-Use or Multi-Use Token.
        4. oauth_token_secret : The Token Secret.
        5. http_request_method *: The HTTP request method used to send the request. Value MUST be uppercase, for example: HEAD, GET, POST, etc.
        6. http_request_uri *: The API Endpoint URL as defined in "Endpoint URLs".
        7. normalized_request_parameters : The result string from step 1.
        8. oauth_nonce *: The request nonce.
        9. oauth_ts *: An integer representing the time of request, expressed in number of seconds after January 1, 1970 00:00:00 GMT.
 
        * required parameters
        
        Examples:
        
        Single-Use Token Request Example
        
        >>> oauth = OAuth()
        >>> consumer_secret = '3a2cd35'
        >>> consumer_key = '0685bd91'
        >>> oauth_token = '540ad18'
        >>> oauth_token_secret = 'x2s55k0'
        >>> nonce = 'MTgzNTYxODk4Mw'
        >>> ts = 1185517832
        >>> http_request_uri = 'http://twitter.com/statuses/friends/123456.json'
        >>> request_params = {'page':3, 'count':50}
        >>> normalized_request_parameters = oauth.normalize_request_parameters(request_params)
        >>> oauth.sign_request(consumer_secret, consumer_key, oauth_token=oauth_token, oauth_token_secret=oauth_token_secret, http_request_uri=http_request_uri, normalized_request_parameters=normalized_request_parameters, oauth_nonce=nonce, oauth_ts=ts)
        'ea48706011440202ee979cb4b337db048e89f889'
        '''
        # TODO add HTTP error code and message to exceptions
        if not 'http_request_uri' in kwargs:
            raise OAuthError
        if not 'oauth_nonce'in kwargs:
            raise OAuthError
        if not 'oauth_ts' in kwargs:
            raise OAuthError
            
        sig_txt = 'oauth_consumer_secret=%s&oauth_consumer_key=%s' % (consumer_secret, consumer_key)
        
        if 'oauth_token' in kwargs:
            sig_txt += '&oauth_token=%s' % kwargs['oauth_token']
        if 'oauth_token_secret' in kwargs:
            sig_txt += '&oauth_token_secret=%s' % kwargs['oauth_token_secret']
            
        if 'http_request_method' in kwargs:
            sig_txt += '&http_request_method=%s' % kwargs['http_request_method'].upper() # request method should be capitalized?
        else:
            sig_txt += '&http_request_method=%s' % DEFAULT_REQUEST_METHOD
        
        sig_txt += '&http_request_uri=%s' % self.escape_http_request_uri(kwargs['http_request_uri'])
        
        if 'normalized_request_parameters' in kwargs:
            sig_txt += '&normalized_request_parameters=%s' % kwargs['normalized_request_parameters']
        
        sig_txt += '&oauth_nonce=%s&oauth_ts=%s' % (str(kwargs['oauth_nonce']), str(kwargs['oauth_ts']))
        
        #print sig_txt
        
        if oauth_sigalg == 'md5':
            import md5
            msg = md5.new(sig_txt)
        elif oauth_sigalg == 'sha1':
            import sha
            msg = sha.new(sig_txt)
        elif oauth_sigalg == 'hmac':
            import hmac
            msg = hmac.new(sig_txt)
        else: # invalid signing algorithm
            raise OAuthError
    
        return msg.hexdigest()
    
    def check_sig(self, oauth_sig, consumer_secret, consumer_key, oauth_sigalg=DEFAULT_SIGALG, **kwargs):
        '''
        Check that the Service Provider creates the same signature as the Consumer-provided one.
        
        >>> oa = OAuth()
        >>> consumer_key = 'asdf'
        >>> consumer_secret = 'asdf'
        >>> nonce = 17907867114999140772853922434221488511
        >>> ts = 1186953553
        >>> http_request_uri = 'https://sp.example.com/oauth/get_su_token'
        >>> expected_sig = '099f1d72df072179f85a71546488519af7338861'
        >>> oa.sign_request(consumer_secret, consumer_key, http_request_uri=http_request_uri, oauth_nonce=nonce, oauth_ts=ts)
        '099f1d72df072179f85a71546488519af7338861'
        >>> oa.check_sig(expected_sig, consumer_secret, consumer_key, http_request_uri=http_request_uri, oauth_nonce=nonce, oauth_ts=ts)
        True
        >>> consumer_key = 'ascf'
        >>> oa.check_sig(expected_sig, consumer_secret, consumer_key, http_request_uri=http_request_uri, oauth_nonce=nonce, oauth_ts=ts)
        False
        '''
        return self.sign_request(consumer_secret, consumer_key, oauth_sigalg=oauth_sigalg, **kwargs) == oauth_sig

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()