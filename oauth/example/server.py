from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

import oauth

REQUEST_TOKEN_URL = 'https://photos.example.net/request_token'
ACCESS_TOKEN_URL = 'https://photos.example.net/access_token'
AUTHORIZATION_URL = 'https://photos.example.net/authorize'
REALM = 'http://photos.example.net/'
CALLBACK_URL = 'http://printer.example.com/request_token_ready'

# example store for one of each thing
class MockOAuthDataStore(object):

    def __init__(self):
        self.consumer = oauth.OAuthConsumer('key', 'secret')
        self.request_token = oauth.OAuthToken('requestkey', 'requestsecret')
        self.access_token = oauth.OAuthToken('accesskey', 'accesssecret')
        self.nonce = 'nonce'
    
    def lookup_consumer(self, key):
        if key == self.consumer.key:
            return self.consumer
        return None
    
    def lookup_token(self, oauth_consumer, token_type, token_token):
        # -> OAuthToken
        raise NotImplementedError
    
    def lookup_nonce(self, oauth_consumer, oauth_token, nonce):
        if oauth_token and oauth_consumer.key == self.consumer.key and (oauth_token.key == self.request_token.key or token.key == self.access_token.key) and nonce == self.nonce:
            return self.nonce
        else:
            raise OAuthError('Nonce not found: %s' % str(nonce))
        return None
    
    def fetch_request_token(self, oauth_consumer):
        if oauth_consumer.key == self.consumer.key:
            return self.request_token
        return None
    
    def fetch_access_token(self, oauth_consumer, oauth_token):
        # -> OAuthToken
        raise NotImplementedError

class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.oauth_server = oauth.OAuthServer(MockOAuthDataStore())
        self.oauth_server.add_signature_method(oauth.OAuthSignatureMethod_PLAINTEXT())
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)
    
    # example way to send an oauth error
    def send_oauth_error(self, err=None):
        # send a 401 error
        self.send_error(401, str(err.message))
        # return the authenticate header
        header = build_authenticate_header(realm=REALM)
        for k, v in header:
            self.send_header(k, v) 
    
    def do_GET(self):
        
        #print self.command, self.path, self.headers
        
        oauth_request = oauth.OAuthRequest.from_request(self.command, self.path, self.headers)
        
        # handle the request based on path
        
        # request token
        if self.path == REQUEST_TOKEN_URL:
            try:
                # create a request token
                token = self.oauth_server.fetch_request_token(oauth_request)
                # send okay response
                self.send_response(200, 'OK')
                self.end_headers()
                # return the token
                self.wfile.write(token.to_string())
            except:
                self.send_oauth_error()
            return
        
    
    def get_consumer(self, params):
        try:
            consumer_key = params['oauth_consumer_key']
        except:
            raise OAuthError('Consumer not found')
            
        # NOTE should get existing consumer from store
        
        # verify the consumer is known to the service provider
        if consumer_key != CONSUMER_KEY:
            raise OAuthError('Consumer not found')
        # get the pre-registered consumer secret
        consumer_secret = CONSUMER_SECRET
        
        # NOTE should return the existing consumer representation instead of creating a new one
        consumer = OAuthConsumer(consumer_key, consumer_secret, REQUEST_TOKEN_ENDPOINT, AUTHORIZATION_ENDPOINT, ACCESS_TOKEN_ENDPOINT)
        return consumer
    
        
        
    '''
    def do_GET(self):
        
        # get the request parameters
        header_params = None
        body_params = None
        url_params = None
        
        try:
            # get the OAuth parameters from the HTTP Authorization header
            header_params = self.service_provider.parse_header_request_parameters(self.headers.getheader('authorization'))
            print header_params
            
            # get the OAuth parameters from the HTTP POST request body
            try:
                content_length = int(self.headers.getheader('content-length'))
                if content_length > 0:
                    body_params = self.service_provider.parse_request_parameters(self.rfile.read(content_length))
            except:
                pass
            
            # get the OAuth parameters from the query string
            url_params = self.service_provider.parse_request_parameters(urlparse.urlparse(self.path).query)
            
            # could specify here which method of passing OAuth parameters is expected or required
            # for this example, we follow the order in spec section 5.2 Consumer Request Parameters
            if header_params:
                params = header_params
            elif body_params:
                params = body_params
            elif url_params:
                params = url_params
            else:
                raise OAuthError('OAuth parameters not found')
        except OAuthError, err:
            self.send_oauth_error(err)
        
        print params
        
        # do something based on the url path
        endpoint = self.service_provider.get_endpoint_url(self.path)
        print endpoint
        
        # Request Token Request
        # verify that the request is valid and return a request token to the consumer
        if endpoint == REQUEST_TOKEN_ENDPOINT: 
            try:
                consumer = self.get_consumer(params)
                if self.service_provider.verify_request_token_request(consumer, params, endpoint):
                        
                    # issue single-use token
                    # IN PRODUCTION, should store the token
                    request_token = OAuthToken(self.service_provider.generate_random_string(), self.service_provider.generate_random_string())
                    
                    # return the OK response
                    self.send_response(200, 'OK')
                    self.end_headers()
                    
                    # return the token
                    self.wfile.write(request_token.encode())
                    
            except OAuthError, err:
                self.send_oauth_error(err)
                
        elif endpoint == AUTHORIZATION_ENDPOINT:
            try:
                if self.service_provider.verify_authorization_request(params):
                    
                    # get the callback url (if one exists)
                    try:
                        callback = params['oauth_callback']
                        print 'Callback url:', callback
                        # IN PRODUCTION, store the callback url
                    except:
                        pass
                    
                    # okay to display the login, pretty boring
                    self.send_response(200, 'OK')
            except OAuthError, err:
                self.send_oauth_error(err)
                
        elif endpoint == ACCESS_TOKEN_ENDPOINT:
            try:
                consumer = self.get_consumer(params)
                if self.service_provider.verify_access_token_request(consumer, client.REQUEST_TOKEN_SECRET, params, endpoint):
                    # issue single-use token
                    # IN PRODUCTION, should store the token
                    access_token = OAuthToken(self.service_provider.generate_random_string(), self.service_provider.generate_random_string(), token_type='access')
                    
                    # return the OK response
                    self.send_response(200, 'OK')
                    self.end_headers()
                    
                    # return the token
                    self.wfile.write(access_token.encode())
                    
            except OAuthError, err:
                self.send_oauth_error(err)
        
        elif endpoint == API_ENDPOINT:
            consumer = self.get_consumer(params)
            try:
                if self.sp.verify_oauth_request(consumer, ACCESS_TOKEN_SECRET, params, endpoint):
                    # okay to grant access to protected resources
                    self.send_response(200, 'OK')
            except OAuthError, err:
                self.send_oauth_error(err)
            
        else:
            # endpoint url not found
            self.send_error(404)
    '''
    
    def do_POST(self):
        return self.do_GET()
        
def main():
    try:
        server = HTTPServer(('', 8080), RequestHandler)
        print 'Test server running...'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()