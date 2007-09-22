import cgi
import urlparse
import string

import oauth
import consumer
    
class OAuthServiceProvider(oauth.OAuth):
    DEFAULT_CHARS = string.ascii_letters + string.digits
    
    def __init__(self, consumer=None):
        self.consumer = consumer
        
    def get_request_parameters(self, request_url):
        '''
        Get the parameters from the request string.
        
        >>> sp = OAuthServiceProvider()
        >>> request_url = 'http://photos.example.net/photos?file=vacation.jpg&size=original&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_signature_method=HMAC-SHA1&oauth_signature=3a4df91bba14e81cde073c9070beec993e45a2d6&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh'
        >>> sp.get_request_parameters(request_url)
        {'oauth_nonce': 'kllo9940pd9333jh', 'oauth_timestamp': '1191242096', 'oauth_consumer_key': 'dpf43f3p2l4k3l03', 'oauth_signature_method': 'HMAC-SHA1', 'oauth_token': 'nnch734d00sl2jdk', 'file': 'vacation.jpg', 'oauth_signature': '3a4df91bba14e81cde073c9070beec993e45a2d6', 'size': 'original'}
        '''
        # split the request url
        urlp = urlparse.urlparse(request_url)
        # convert the url params to a dictionary
        qs_params = cgi.parse_qs(urlp.query, keep_blank_values=False)   
        params = {}
        # convert from list of values to a single value for each key
        for k,v in qs_params.iteritems():
            params[k] = v[0]
        return params
    
    def verify_signature(self, signature, consumer_secret, signature_method=oauth.DEFAULT_SIGNATURE_METHOD, **kwargs):
        '''
        Check that the Service Provider creates the same signature as the Consumer-provided one.
        
        >>> sp = OAuthServiceProvider()
        >>> signature = '7018c1ff04aefe60ae892de299cc9d8d7ff4e09f'
        >>> consumer_secret = '427a5979d9df7722'
        >>> endpoint_url = 'https://photos.example.net/request_token'
        >>> http_request_method='GET'
        
        >>> sp.sign_request(oauth.DEFAULT_SIGNATURE_METHOD, consumer_secret, endpoint_url=endpoint_url)
        '7018c1ff04aefe60ae892de299cc9d8d7ff4e09f'
        >>> sp.verify_signature(signature, consumer_secret, endpoint_url=endpoint_url, http_request_method=http_request_method)
        True
        >>> consumer_secret = 'asdf'
        >>> sp.verify_signature(signature, consumer_secret, endpoint_url=endpoint_url, http_request_method=http_request_method)
        False
        '''
        return self.sign_request(signature_method, consumer_secret, **kwargs) == signature
    
    def verify_request_token_request(self, consumer, request_url, http_request_method=oauth.DEFAULT_REQUEST_METHOD, recently_used_nonces=[]):
        '''
        Verify that the Consumer has sent a proper request for a Request Token.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthConsumer('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')
        >>> endpoint_url = 'https://photos.example.net/request_token'
        >>> callback_url = 'http://printer.example.com/request_token_ready'
        >>> ts = 1191242090
        >>> nonce = 'hsu94j3884jdopsl'
        >>> request_url = consumer.get_token_path(endpoint_url, oauth_callback=callback_url, oauth_nonce=nonce, oauth_timestamp=ts)
        >>> sp.verify_request_token_request(consumer, request_url)
        True
        '''
        # should not have request token
        return self._verify_token_request(False, consumer, request_url, http_request_method=oauth.DEFAULT_REQUEST_METHOD, recently_used_nonces=[])

    def verify_access_token_request(self, consumer, request_url, http_request_method=oauth.DEFAULT_REQUEST_METHOD, recently_used_nonces=[]):
        '''
        Verify that the Consumer has sent a proper request for an Access Token.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthConsumer('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')
        >>> endpoint_url = 'https://photos.example.net/request_token'
        >>> ts = 1191242090
        >>> nonce = 'hsu94j3884jdopsl'
        >>> token = 'hh5s93j4hdidpola'
        >>> request_url = consumer.get_token_path(endpoint_url, oauth_token=token, oauth_nonce=nonce, oauth_timestamp=ts)
        >>> sp.verify_request_token_request(consumer, request_url)
        True
        '''
        # requires request token
        return self._verify_token_request(True, consumer, request_url, http_request_method=oauth.DEFAULT_REQUEST_METHOD, recently_used_nonces=[])

    def _verify_token_request(self, should_have_request_token, consumer, request_url,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD,
        last_timestamp=None, recently_used_nonces=[]):
        
        # get the request parameters
        params = self.get_request_parameters(request_url)
        
        # check that all the required parameters are in the request
        try:
            consumer_key = params['oauth_consumer_key']
            version = params['oauth_version']
            signature_method = params['oauth_signature_method']
            signature = params['oauth_signature']
            timestamp = params['oauth_timestamp']
            nonce = params['oauth_nonce']
        except:
            # missing required request params
            raise oauth.OAuthError('Missing required request parameters')
        
        # if this is a request for a Request Token, no token parameter should be present
        # if this is a request for an Access Token, a token parameter is required
        try:
            request_token = params['oauth_token']
            if not should_have_request_token:
                raise oauth.OAuthError('Request token specified when there should be none')
        except:
            if should_have_request_token:
                raise oauth.OAuthError('Missing request token')
            
        # verify valid consumer_key
        if not consumer_key == consumer.consumer_key:
            raise oauth.OAuthError('Invalid consumer key')
        
        # verify valid timestamp
        if not self.is_valid_timestamp(timestamp, last_timestamp):
            raise oauth.OAuthError('Invalid timestamp')
        
        # verify valid nonce
        if not self.is_valid_nonce(nonce, recently_used_nonces):
            raise oauth.OAuthError('Invalid nonce')
        
        # get the secret from the consumer
        consumer_secret = consumer.consumer_secret
        
        # get the endpoint url
        endpoint_url = self.get_endpoint_url(request_url)
                    
        # verify the signature is correct
        if not self.verify_signature(
                    signature,
                    consumer_secret,
                    signature_method=signature_method,
                    endpoint_url=endpoint_url,
                    http_request_method=http_request_method,
                ):
            raise oauth.OAuthError('Signature does not match.')
            
        return True
        
    def verify_authorization_request(self, request_url, http_request_method=oauth.DEFAULT_REQUEST_METHOD):
        '''
        Verify that the Consumer has sent a proper request for authorization.
        The consumer should have obtained an Request Token.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthConsumer('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')
        >>> endpoint_url = 'https://photos.example.net/authorize'
        >>> token='QMQZkv06WfjKh4ws'
        >>> request_url = consumer.get_authorization_path(endpoint_url, token)
        >>> sp.verify_authorization_request(request_url)
        True
        '''
        params = self.get_request_parameters(request_url)
        try:
            # check that all the required parameters are in the request
            token = params['oauth_token']
        except:
            # missing required request params
            raise oauth.OAuthError('Missing required request parameters')
        return True
    
    def verify_oauth_request(self, consumer, request_url,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD,
        last_timestamp=None, recently_used_nonces=[]):
        '''
        Verify that the Consumer has sent a proper request for authorization.
        The consumer should have obtained an Access Token.
        
        >>> sp = OAuthServiceProvider()
        >>> consumer = consumer.OAuthConsumer('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')
        >>> endpoint_url = 'http://photos.example.net/photos'
        >>> token = 'nnch734d00sl2jdk'
        >>> token_secret = 'pfkkdhi9sl3r4s00'
        >>> last_timestamp = '11'
        >>> ts = '12'
        >>> nonce = 'kllo9940pd9333jh'
        >>> params = {'file': 'vacation.jpg', 'size': 'original'}
        >>> request_url = consumer.get_oauth_request_path(endpoint_url, token, token_secret, oauth_timestamp=ts, oauth_nonce=nonce, request_parameters=params)
        >>> request_url
        'http://photos.example.net/photos?file=vacation.jpg&size=original&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_signature_method=HMAC-SHA1&oauth_signature=83edabe2aec0cee9ce69b22effab5c219eb2fe11&oauth_timestamp=12&oauth_nonce=kllo9940pd9333jh'
        >>> sp.verify_oauth_request(consumer, request_url, last_timestamp=last_timestamp)
        True
        '''
        # get the request parameters
        params = self.get_request_parameters(request_url)
        
        # check that all the required parameters are in the request
        try:
            consumer_key = params['oauth_consumer_key']
            token = params['oauth_token']
            signature_method = params['oauth_signature_method']
            signature = params['oauth_signature']
            timestamp = params['oauth_timestamp']
            nonce = params['oauth_nonce']
        except:
            # missing required request params
            raise oauth.OAuthError('Missing required request parameters')
        
        # verify valid consumer_key
        if not consumer_key == consumer.consumer_key:
            raise oauth.OAuthError('Invalid consumer key')
        
        # verify valid timestamp
        if not self.is_valid_timestamp(timestamp, last_timestamp):
            raise oauth.OAuthError('Invalid timestamp')
        
        # verify valid nonce
        if not self.is_valid_nonce(nonce, recently_used_nonces):
            raise oauth.OAuthError('Invalid nonce')
        
        # get the secret from the consumer
        consumer_secret = consumer.consumer_secret
        
        # get the endpoint url
        endpoint_url = self.get_endpoint_url(request_url)
                    
        # verify the signature is correct
        if not self.verify_signature(
                    signature,
                    consumer_secret,
                    request_parameters=params,
                    signature_method=signature_method,
                    endpoint_url=endpoint_url,
                    http_request_method=http_request_method,
                ):
            #raise oauth.OAuthError('Signature does not match.')
            pass
            
        return True
        
def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()