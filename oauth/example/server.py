'''
Stupid simple webserver for testing OAuth Service Provider functions.
Please don't use this for anything except testing.
'''
import urlparse
import pickle
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

from oauth.oauth import OAuthError, OAuthToken
from oauth.service_provider import OAuthServiceProvider
from oauth.consumer import OAuthConsumer

# should match client.py consumer key and secret
CONSUMER_KEY = '1b20acc6'
CONSUMER_SECRET = '427a5979d9df7722'

SU_TOKEN_ENDPOINT = '/oauth/get_su_token'
AUTHORIZATION_ENDPOINT = '/oauth/authorize'

class RequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.sp = OAuthServiceProvider()
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        params = self.sp.get_request_parameters(self.path)
        try:
            consumer_key = params['oauth_consumer_key']
            # get the pre-registered consumer secret
            consumer_secret = CONSUMER_SECRET
            consumer = OAuthConsumer(consumer_key, consumer_secret)
        except:
            self.send_error(401, 'Invalid consumer key.')
        
        # do something based on the url path
        endpoint = urlparse.urlparse(self.path).path
        
        #print endpoint
        
        if endpoint == SU_TOKEN_ENDPOINT:
            # desktop consumer requested a single-use token 
            try:
                if self.sp.verify_single_use_token_request(consumer, self.path, self.command):
                    # issue single-use token
                    # in production, should check that the token is unique
                    token = OAuthToken(self.sp.generate_random_string(), self.sp.generate_random_string())
                    # return the token
                    # in production, could format the response as xml, json etc...
                    self.wfile.write(pickle.dumps(token))
                    self.send_response(200, 'OK') 
            except OAuthError, err:
                self.send_error(401, err.message)
        elif endpoint == AUTHORIZATION_ENDPOINT:
            try:
                if self.sp.verify_desktop_authorization_request(consumer, self.path, self.command):
                    # okay to display the login
                    self.send_response(200, 'OK')
            except OAuthError, err:
                self.send_error(401, err.message)
        else:
            # endpoint url not found
            self.send_error(404)     
        
def main():
    try:
        server = HTTPServer(('', 8080), RequestHandler)
        print 'Test server running...'
        server.serve_forever()
    except KeyboardInterrupt:
        server.socket.close()

if __name__ == '__main__':
    main()