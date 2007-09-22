import httplib

import oauth

class OAuthConsumer(oauth.OAuth):
    ports_by_security = { True: httplib.HTTPS_PORT, False: httplib.HTTP_PORT }
    
    # Path for obtaining a Token
    token_path = ('%s?oauth_consumer_key=%s'
                    '%s' # oauth_callback (optional)
                    '%s' # oauth_token (access token requests only)
                    '&oauth_version=%s'
                    '&oauth_signature_method=%s'
                    '&oauth_signature=%s'
                    '&oauth_timestamp=%s'
                    '&oauth_nonce=%s')
                    
    # Path to authorize a User (get login page)
    authorize_path = '%s?oauth_token=%s'
    
    # Path to make an OAuth authorized request
    oauth_request_path = ('%s?'
            '%s' # optional non-oauth parameters
            '&oauth_consumer_key=%s'
            '&oauth_token=%s'
            '&oauth_signature_method=%s'
            '&oauth_signature=%s'
            '&oauth_timestamp=%s'
            '&oauth_nonce=%s'
        )
                    
    def __init__(self, oauth_consumer_key, oauth_consumer_secret,
        is_secure_connection=False, server=None, port=None):
        
        # consumer properties
        self.consumer_key = oauth_consumer_key
        self.consumer_secret = oauth_consumer_secret
        
        if not port:
            port = self.ports_by_security[is_secure_connection]
        
        # set up a http connection
        if (is_secure_connection):
            self.connection = httplib.HTTPSConnection("%s:%d" % (server, port))
        else:
            self.connection = httplib.HTTPConnection("%s:%d" % (server, port))
    
    def get_request_token(self, endpoint_url, oauth_callback='',
        oauth_nonce=None, oauth_timestamp=None, oauth_signature_method=oauth.DEFAULT_SIGNATURE_METHOD,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=True):
        
        # generate a timestamp and nonce if none are specified
        oauth_timestamp, oauth_nonce = self.get_timestamp_nonce(oauth_timestamp, oauth_nonce)
        
        # Get the request path
        path = self.get_token_path(
            endpoint_url,
            oauth_callback=oauth_callback,
            oauth_nonce=oauth_nonce,
            oauth_timestamp=oauth_timestamp, 
            oauth_signature_method=oauth_signature_method, 
            http_request_method=http_request_method,
        )
        
        # TODO create the headers
        if generate_header:
            pass
        
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()
    
    def request_authorization(self, endpoint_url, oauth_token,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=True):
        
        path = self.get_authorization_path(endpoint_url, oauth_token)
        
        # TODO create the headers
        if generate_header:
            pass
        
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()  
    
    def get_access_token(self, endpoint_url, oauth_token,
        oauth_nonce=None, oauth_timestamp=None, oauth_signature_method=oauth.DEFAULT_SIGNATURE_METHOD,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=True):
        
        # generate a timestamp and nonce if none are specified
        oauth_timestamp, oauth_nonce = self.get_timestamp_nonce(oauth_timestamp, oauth_nonce)
        
        # Get the request path
        path = self.get_token_path(
            endpoint_url,
            oauth_token=oauth_token,
            oauth_nonce=oauth_nonce,
            oauth_timestamp=oauth_timestamp, 
            oauth_signature_method=oauth_signature_method, 
            http_request_method=http_request_method,
        )
        
        # TODO create the headers
        if generate_header:
            pass
        
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()
    
    def oauth_request(self, endpoint_url, oauth_token, oauth_token_secret,
        oauth_timestamp=None, oauth_nonce=None, request_parameters={},
        oauth_signature_method=oauth.DEFAULT_SIGNATURE_METHOD,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=True):
        
        # generate a timestamp and nonce if none are specified
        oauth_timestamp, oauth_nonce = self.get_timestamp_nonce(oauth_timestamp, oauth_nonce)
        
        # Get the request path
        path = self.get_token_path(
            endpoint_url,
            oauth_token=oauth_token,
            oauth_nonce=oauth_nonce,
            oauth_timestamp=oauth_timestamp, 
            oauth_signature_method=oauth_signature_method, 
            http_request_method=http_request_method,
        )
        
        # TODO create the headers
        if generate_header:
            pass
        
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()
    
    def get_authorization_path(self, endpoint_url, oauth_token):
        '''
        Get the path for the user to login.
        
        >>> consumer = OAuthConsumer('0685bd91', '427a5979d9df7722')
        >>> endpoint_url = 'http://sp.example.com/oauth/authorize'
        >>> token = '37bb49b4'
        >>> consumer.get_authorization_path(endpoint_url, token)
        'http://sp.example.com/oauth/authorize?oauth_token=37bb49b4'
        '''
        return self.authorize_path % (endpoint_url, oauth_token)
    
    def get_token_path(self, endpoint_url,
        oauth_callback='', oauth_token='',
        oauth_nonce=None, oauth_timestamp=None, 
        oauth_signature_method=oauth.DEFAULT_SIGNATURE_METHOD,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD):
        '''        
        Get either the Request Token or Access Token path for a consumer. This method can be used
        for a consumer that wishes to make it's own web request but would like to get the
        full api path.
        
        This method does not care if a callback url or token is supplied.
        
        >>> consumer = OAuthConsumer('1b20acc6', '427a5979d9df7722')
        >>> nonce = 17907867114999140772853922434221488511
        >>> ts = 1191242090
        
        >>> endpoint_url = 'https://sp.example.com/oauth/request_token'
        >>> callback = 'http://consumer.example.com/request_token_ready'
        >>> consumer.get_token_path(endpoint_url, oauth_callback=callback, oauth_nonce=nonce, oauth_timestamp=ts)
        'https://sp.example.com/oauth/request_token?oauth_consumer_key=1b20acc6&oauth_callback=http%3A%2F%2Fconsumer.example.com%2Frequest_token_ready&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_signature=06dd19b8500b11f2996dd7f341683967171881e2&oauth_timestamp=1191242090&oauth_nonce=17907867114999140772853922434221488511'
        
        >>> endpoint_url = 'https://sp.example.com/oauth/access_token'
        >>> token = 'VVHaCVLiMzTWOmEI'
        >>> consumer.get_token_path(endpoint_url, oauth_token=token, oauth_nonce=nonce, oauth_timestamp=ts)
        'https://sp.example.com/oauth/access_token?oauth_consumer_key=1b20acc6&oauth_token=VVHaCVLiMzTWOmEI&oauth_version=1.0&oauth_signature_method=HMAC-SHA1&oauth_signature=d99d2a44f38c0ddc67a865f5c96f02c0ebf36ea5&oauth_timestamp=1191242090&oauth_nonce=17907867114999140772853922434221488511'
        '''

        # generate a timestamp and nonce if none are specified
        oauth_timestamp, oauth_nonce = self.get_timestamp_nonce(oauth_timestamp, oauth_nonce)
            
        # sign the request
        oauth_signature = self.sign_request(
            oauth_signature_method,
            self.consumer_secret,
            endpoint_url=endpoint_url,
            http_request_method=http_request_method,
        )  
        
        if oauth_callback:
            oauth_callback = '&oauth_callback=%s' % self.escape(oauth_callback)
            
        if oauth_token:
            oauth_token = '&oauth_token=%s' % oauth_token
            
        # generate the request path
        path = self.token_path % (
            endpoint_url,
            self.consumer_key,
            oauth_callback,
            oauth_token,
            self.oauth_version,
            oauth_signature_method,
            oauth_signature,
            oauth_timestamp,
            oauth_nonce
        )
        return path
        
    def get_oauth_request_path(self, endpoint_url, oauth_token, oauth_token_secret,
        oauth_timestamp=None, oauth_nonce=None, request_parameters={},
        oauth_signature_method=oauth.DEFAULT_SIGNATURE_METHOD,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD):
        '''        
        Get the request path for an oauth authorized request.
        
        >>> consumer = OAuthConsumer('dpf43f3p2l4k3l03', 'kd94hf93k423kf44')
        >>> endpoint_url = 'http://photos.example.net/photos'
        >>> token = 'nnch734d00sl2jdk'
        >>> token_secret = 'pfkkdhi9sl3r4s00'
        >>> ts = 1191242096
        >>> nonce = 'kllo9940pd9333jh'
        >>> params = {'file': 'vacation.jpg', 'size': 'original'}
        >>> consumer.get_oauth_request_path(endpoint_url, token, token_secret, oauth_timestamp=ts, oauth_nonce=nonce, request_parameters=params)
        'http://photos.example.net/photos?file=vacation.jpg&size=original&oauth_consumer_key=dpf43f3p2l4k3l03&oauth_token=nnch734d00sl2jdk&oauth_signature_method=HMAC-SHA1&oauth_signature=3a4df91bba14e81cde073c9070beec993e45a2d6&oauth_timestamp=1191242096&oauth_nonce=kllo9940pd9333jh'
        '''
        # join the non-oauth parameters for the path
        param_str = '&'.join('%s=%s' % (k, v) for k, v in request_parameters.iteritems())
        
        # generate a timestamp and nonce if none are specified
        oauth_timestamp, oauth_nonce = self.get_timestamp_nonce(oauth_timestamp, oauth_nonce)
            
        # add oauth specific parameters to the request parameters
        request_parameters['oauth_consumer_key'] = self.consumer_key
        request_parameters['oauth_token'] = oauth_token
        request_parameters['oauth_signature_method'] = oauth_signature_method
        request_parameters['oauth_timestamp'] = oauth_timestamp
        request_parameters['oauth_nonce'] = oauth_nonce
            
        # sign the request
        oauth_signature = self.sign_request(
            oauth_signature_method,
            self.consumer_secret,
            endpoint_url=endpoint_url,
            request_parameters=request_parameters,
            http_request_method=http_request_method,
            token_secret=oauth_token_secret,
        )
                    
        # generate the request path
        path = self.oauth_request_path % (
            endpoint_url,
            param_str,
            self.consumer_key,
            oauth_token,
            oauth_signature_method,
            oauth_signature,
            oauth_timestamp,
            oauth_nonce
        )
        return path
    
    def get_timestamp_nonce(self, timestamp=None, nonce=None):
        # generate a timestamp if none is specified
        if timestamp is None:
            timestamp=self.generate_timestamp()
        # generate a nonce if none is specified
        if nonce is None:
            nonce=self.generate_nonce()
        return timestamp, nonce
            

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()