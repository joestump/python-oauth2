'''
Stupid simple webserver for testing OAuth Service Provider functions.
Please don't use this for anything except testing.
Also please note where addtional verification of consumer requests is necessary.
'''

import urlparse
import pickle
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from oauth.oauth import OAuthError, OAuthToken
from oauth.service_provider import OAuthServiceProvider
from oauth.consumer import OAuthConsumer

# example from the Appendix A
CONSUMER_KEY = 'dpf43f3p2l4k3l03'
CONSUMER_SECRET = 'kd94hf93k423kf44'

# service provider endpoint urls
REQUEST_TOKEN_ENDPOINT = 'https://photos.example.net/request_token'
AUTHORIZATION_ENDPOINT = 'https://photos.example.net/authorize'
ACCESS_TOKEN_ENDPOINT = 'https://photos.example.net/access_token'
API_ENDPOINT = 'http://photos.example.net/photos'

class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.sp = OAuthServiceProvider()
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        
        # do something based on the url path
        params = self.sp.get_request_parameters(self.path)
        endpoint = self.sp.get_endpoint_url(self.path)
        
        if endpoint == REQUEST_TOKEN_ENDPOINT:
            # consumer requested a request token 
            consumer = get_consumer(params)
            try:
                if self.sp.verify_request_token_request(consumer, self.path, self.command):
                    # get the callback url (if one exists)
                    try:
                        callback_url = params['oauth_callback']
                        print 'Callback url: ', callback_url
                        # IN PRODUCTION, store the callback url
                    except:
                        pass
                    # issue single-use token
                    # IN PRODUCTION, should store the token
                    token = OAuthToken(self.sp.generate_random_string(), self.sp.generate_random_string())
                    # return the token
                    self.wfile.write(pickle.dumps(token))
                    # return the OK response
                    self.send_response(200, 'OK') 
            except OAuthError, err:
                self.send_error(401, err.message)
                
        elif endpoint == AUTHORIZATION_ENDPOINT:
            try:
                if self.sp.verify_authorization_request(self.path, self.command):
                    # okay to display the login
                    self.send_response(200, 'OK')
            except OAuthError, err:
                self.send_error(401, err.message)
                
        elif endpoint == ACCESS_TOKEN_ENDPOINT:
            # consumer requested an access token 
            consumer = get_consumer(params)
            try:
                if self.sp.verify_access_token_request(consumer, self.path, self.command):
                    # issue single-use token
                    # IN PRODUCTION, should store the token
                    token = OAuthToken(self.sp.generate_random_string(), self.sp.generate_random_string(), token_type='access')
                    # return the token
                    self.wfile.write(pickle.dumps(token))
                    # return the OK response
                    self.send_response(200, 'OK') 
            except OAuthError, err:
                self.send_error(401, err.message)
        
        elif endpoint == API_ENDPOINT:
            consumer = get_consumer(params)
            try:
                if self.sp.verify_oauth_request(consumer, self.path, self.command):
                    # okay to grant access to protected resources
                    self.send_response(200, 'OK')
            except OAuthError, err:
                self.send_error(401, err.message)
                
        else:
            # endpoint url not found
            self.send_error(404)     

def get_consumer(params):
    try:
        consumer_key = params['oauth_consumer_key']
        # IN PRODUCTION, get the pre-registered consumer secret
        consumer_secret = CONSUMER_SECRET
        return OAuthConsumer(consumer_key, consumer_secret)
    except:
        self.send_error(401, 'Invalid consumer key.')
        
def main():
    try:
        server = HTTPServer(('', 8080), RequestHandler)
        print 'Test server running...'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()