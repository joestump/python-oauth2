import httplib
import urllib

import oauth

class OAuthConsumer(oauth.OAuth):
    ports_by_security = { True: httplib.HTTPS_PORT, False: httplib.HTTP_PORT }
    
    # Path for subsequent requests
    request_path = ('%s?oauth_consumer_key=%s'
                '&oauth_token=%s'
                '&oauth_nonce=%s'
                '&oauth_ts=%s'
                '%s' # normalized request params (optional)
                '&oauth_sigalg=%s'
                '&oauth_sig=%s')
                    
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
        
    def get_oauth_request_path(self, http_request_uri,
        oauth_token, oauth_token_secret, request_parameters=None,
        oauth_nonce=None, oauth_ts=None,
        oauth_sigalg=oauth.DEFAULT_SIGALG, request_method=oauth.DEFAULT_REQUEST_METHOD):
        '''
        Get the path for a general consumer OAuth request.
        The consumer must already have obtained a multi-use token.
        
        >>> consumer = OAuthConsumer('asdf', 'asdf')
        >>> token = '37bb49b4'
        >>> token_secret = '37bb49b4'
        >>> request_parameters = {'page': 3, 'count': 50, 'friends': 18, 'type': 'file'}
        >>> http_request_uri = 'http://api.pownce.com/notes/from/kevin'
        >>> nonce = 17907867114999140772853922434221488511
        >>> ts = 1186953553
        >>> consumer.get_oauth_request_path(http_request_uri, token, token_secret, request_parameters=request_parameters, oauth_nonce=nonce, oauth_ts=ts)
        'http://api.pownce.com/notes/from/kevin?oauth_consumer_key=asdf&oauth_token=37bb49b4&oauth_nonce=17907867114999140772853922434221488511&oauth_ts=1186953553&request_parameters=count%3D50%26friends%3D18%26page%3D3%26type%3Dfile&oauth_sigalg=sha1&oauth_sig=fd86a1eba51b413ce533ff88ce21109cedb6c253'
        '''
        if oauth_nonce is None:
            oauth_nonce = self.generate_nonce()
        if oauth_ts is None:
            oauth_ts = self.generate_timestamp()
        normalized_params = None
        np_url = ''
        if request_parameters:
            normalized_params = self.normalize_request_parameters(request_parameters)
            np_url = '&request_parameters=%s' % normalized_params
        # sign the request
        oauth_sig = self.sign_request(
            self.consumer_secret,
            self.consumer_key,
            oauth_sigalg=oauth_sigalg,
            oauth_token=oauth_token,
            oauth_token_secret=oauth_token_secret,
            request_method=request_method,
            http_request_uri=http_request_uri,
            normalized_params=normalized_params,
            oauth_nonce=oauth_nonce,
            oauth_ts=oauth_ts
        )    
        # generate the request path
        path = self.request_path % (
            http_request_uri,
            self.consumer_key,
            oauth_token,
            oauth_nonce,
            oauth_ts,
            np_url,
            oauth_sigalg,
            oauth_sig
        )
        return path

# Web Application Consumer
class OAuthWebConsumer(OAuthConsumer):
    # Path to login a web consumer user
    su_token_path = ('%s?oauth_consumer_key=%s'
                    '%s' # optional oauth_state parameter
                    '&oauth_sig=%s')
                    
    def request_authorization(self):
        pass
        
# Desktop Consumer
class OAuthDesktopConsumer(OAuthConsumer):

    # Path for obtaining a desktop consumer Single-Use Token
    su_token_path = ('%s?oauth_consumer_key=%s'
                    '&oauth_nonce=%s'
                    '&oauth_ts=%s'
                    '&oauth_sigalg=%s'
                    '&oauth_sig=%s')
                    
    # Path to login a desktop consumer user
    authorize_path = '%s?oauth_consumer_key=%s&oauth_token=%s'
                       
    def get_single_use_token(self, http_request_uri,
        oauth_nonce=None, oauth_ts=None, oauth_sigalg=oauth.DEFAULT_SIGALG,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=False):
        
        # generate a nonce if none is specified
        if oauth_nonce is None:
            oauth_nonce=self.generate_nonce()
        
        # generate a timestamp if none is specified
        if oauth_ts is None:
            oauth_ts=self.generate_timestamp()
        
        # Get the request path
        path = self.get_single_use_token_path(
            http_request_uri,
            oauth_nonce,
            oauth_ts, 
            oauth_sigalg=oauth_sigalg, 
            http_request_method=http_request_method,
        )
        
        # TODO create the headers if desired
        
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()
    
    def request_authorization(self, http_request_uri, oauth_token,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD, generate_header=False):
        
        path = self.get_authorize_path(
            http_request_uri,
            oauth_token
        )
        
        # TODO create the headers
        self.connection.request(http_request_method, path)
        return self.connection.getresponse()
        
    def get_single_use_token_path(self, http_request_uri,
        oauth_nonce=None, oauth_ts=None, oauth_sigalg=oauth.DEFAULT_SIGALG,
        http_request_method=oauth.DEFAULT_REQUEST_METHOD):
        '''        
        Get the single-use token path for a desktop client. This method can be used
        for a consumer that wishes to make it's own web request but would like to get the
        full api path.
        
        >>> consumer = OAuthDesktopConsumer('1b20acc6', '427a5979d9df7722')
        >>> nonce = 17907867114999140772853922434221488511
        >>> ts = 1186953553
        >>> http_request_uri = 'https://sp.example.com/oauth/get_su_token'
        >>> consumer.get_single_use_token_path(http_request_uri, nonce, ts)
        'https://sp.example.com/oauth/get_su_token?oauth_consumer_key=1b20acc6&oauth_nonce=17907867114999140772853922434221488511&oauth_ts=1186953553&oauth_sigalg=sha1&oauth_sig=66c9ca53fc7302e5cec1395c9b7e51717f324dd6'
        '''
        
        # generate a nonce if none is specified
        if oauth_nonce is None:
            oauth_nonce=self.generate_nonce()
        
        # generate a timestamp if none is specified
        if oauth_ts is None:
            oauth_ts=self.generate_timestamp()

        # sign the request
        oauth_sig = self.sign_request(
            self.consumer_secret,
            self.consumer_key,
            oauth_sigalg=oauth_sigalg,
            http_request_method=http_request_method,
            http_request_uri=http_request_uri,
            oauth_nonce=oauth_nonce,
            oauth_ts=oauth_ts
        )  
        
        # generate the request path
        path = self.su_token_path % (
            http_request_uri,
            self.consumer_key,
            oauth_nonce,
            oauth_ts,
            oauth_sigalg,
            oauth_sig
        )
        return path
    
    def get_authorize_path(self, http_request_uri, oauth_token):
        '''
        Get the path for the user to login and exchange the single-use token
        for a multi-use token.
        
        >>> consumer = OAuthDesktopConsumer('0685bd91', '427a5979d9df7722')
        >>> http_request_uri = 'http://sp.example.com/oauth/authorize'
        >>> token = '37bb49b4'
        >>> consumer.get_authorize_path(http_request_uri, token)
        'http://sp.example.com/oauth/authorize?oauth_consumer_key=0685bd91&oauth_token=37bb49b4'
        '''
        # generate the request path
        path = self.authorize_path % (
            http_request_uri,
            self.consumer_key,
            oauth_token
        )
        return path

def _test():
    import doctest
    doctest.testmod()

if __name__ == "__main__":
    _test()