import cgi
import urlparse
import string

import oauth
import consumer

# Path to obtain a Multi-Use Token             
LOGIN_PATH = ('%s?oauth_consumer_key=%s'
                '%s' # spot for optional single-use token & token secret
                '&oauth_nonce=%s'
                '&oauth_ts=%s'
                '&oauth_sigalg=%s'
                '&oauth_sig=%s')
    
class OAuthServiceProvider(oauth.OAuth):
    DEFAULT_CHARS = string.ascii_letters + string.digits
    
    def __init__(self, consumer=None):
        self.consumer = consumer
        
    def get_request_parameters(self, request_url):
        # split the request url
        urlp = urlparse.urlparse(request_url)
        # convert the url params to a dictionary
        qs_params = cgi.parse_qs(urlp.query, keep_blank_values=False)   
        params = {}
        # convert from list of values to a single value for each key
        for k,v in qs_params.iteritems():
            params[k] = v[0]
        return params

    def verify_single_use_token_request(self, consumer, request_url,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, used_nonces=[]):
        '''
        Verify that the Consumer has sent a proper request for a single-use token.
        
        The consumer should have both a consumer_key and a consumer_secret which should be obtained from
        some sort of storage by the service provider.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthDesktopConsumer('1b20acc6', '427a5979d9df7722')
        >>> request_url = consumer.get_single_use_token_path('https://sp.example.com/oauth/get_su_token')
        >>> sp.verify_single_use_token_request(consumer, request_url)
        True
        '''
        params = self.get_request_parameters(request_url)
        try:
            # check that all the required parameters are in the request
            consumer_key = params['oauth_consumer_key']
            nonce = params['oauth_nonce']
            ts = params['oauth_ts']
            sig = params['oauth_sig']
        except:
            # missing required request params
            raise oauth.OAuthError('Missing request params')
            
        # verify valid consumer_key
        if not consumer_key == consumer.consumer_key:
            raise oauth.OAuthError('Invalid consumer key')
        
        # verify valid timestamp
        if not self.is_valid_timestamp(ts):
            raise oauth.OAuthError('Invalid timestamp')
        
        # verify valid nonce
        if not self.is_valid_nonce(nonce, used_nonces):
            raise oauth.OAuthError('Invalid nonce')
        
        # get the signing algorithm
        sigalg = oauth.DEFAULT_SIGALG
        if 'oauth_sigalg' in params:
            sigalg = params['oauth_sigalg']
        
        # get the secret from the consumer
        consumer_secret = consumer.consumer_secret
        
        # get the full request uri and escape it
        http_request_uri = self.get_http_request_uri(request_url)
                    
        # verify the signature is correct
        if not self.check_sig(
                    sig,
                    consumer_secret,
                    consumer_key,
                    oauth_sigalg=sigalg,
                    http_request_uri=http_request_uri,
                    oauth_nonce=nonce,
                    oauth_ts=ts,
                    http_request_method=http_request_method,
                ):
            raise oauth.OAuthError('Signature does not match.')
        # yesssss
        return True
        
    def verify_desktop_authorization_request(self, consumer, request_url,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, used_nonces=[]):
        '''
        Verify that the Consumer has sent a proper request for authorization.
        
        The consumer should have both a consumer_key and a consumer_secret which should be obtained from
        some sort of storage by the service provider.
        
        The consumer should have also obtained a single-use token.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthDesktopConsumer('1b20acc6', '427a5979d9df7722')
        >>> token = oauth.OAuthToken(token='QMQZkv06WfjKh4ws', secret='Rf4g7EkOLkDJEkzj')
        >>> http_request_uri = 'https://sp.example.com/oauth/authorize'
        >>> request_url = consumer.get_authorize_path(http_request_uri, token.token)
        >>> sp.verify_desktop_authorization_request(consumer, request_url)
        True
        '''
        params = self.get_request_parameters(request_url)
        try:
            # check that all the required parameters are in the request
            consumer_key = params['oauth_consumer_key']
            token = params['oauth_token']
        except:
            # missing required request params
            raise oauth.OAuthError('Missing request params')
        
        # verify valid consumer_key
        if not consumer_key == consumer.consumer_key:
            raise oauth.OAuthError('Invalid consumer key')
        return True
        
def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()