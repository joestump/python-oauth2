'''
Example consumer.
'''
import httplib
import time
import oauth

SERVER = 'localhost'
PORT = 8080

REQUEST_TOKEN_URL = 'https://photos.example.net/request_token'
ACCESS_TOKEN_URL = 'https://photos.example.net/access_token'
AUTHORIZATION_URL = 'https://photos.example.net/authorize'
CALLBACK_URL = 'http://printer.example.com/request_token_ready'

# key and secret granted by the service provider for this consumer application - same as the MockOAuthDataStore
CONSUMER_KEY = 'key'
CONSUMER_SECRET = 'secret'

# example client using httplib with headers
class SimpleOAuthClient(oauth.OAuthClient):

    def __init__(self, server, port=httplib.HTTP_PORT, request_token_url='', access_token_url=''):
        self.server = server
        self.port = port
        self.request_token_url = request_token_url
        self.access_token_url = access_token_url
        self.connection = httplib.HTTPConnection("%s:%d" % (self.server, self.port))
    
    def fetch_request_token(self, oauth_request):
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.request_token_url, headers=oauth_request.to_header())  
        response = self.connection.getresponse()
        return oauth.OAuthToken.from_string(response.read())
        
    def fetch_access_token(self, oauth_request):
        # -> OAuthToken
        self.connection.request(oauth_request.http_method, self.access_token_url, body, headers)  
        print self.connection.getresponse()

def run_example():

    # setup
    print '** OAuth Python Library Example **'
    client = SimpleOAuthClient(SERVER, PORT, REQUEST_TOKEN_URL, ACCESS_TOKEN_URL)
    consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
    signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
    pause()
    
    # get request token
    print '* Obtain a request token ...'
    pause()
    oauth_request = oauth.OAuthRequest.from_consumer_and_token(consumer, http_url=client.request_token_url)
    oauth_request.sign_request(signature_method_plaintext, consumer, None)
    token = client.fetch_request_token(oauth_request)
    print 'key: %s' % str(token.key)
    print 'secret: %s' % str(token.secret)
    pause()
    
    print '* Authorize the request token ...'
    pause()
    
    # get access token
    
    
    
'''  
def old_run_example():

    print '*** OAuth Example ***'
    consumer = OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET, REQUEST_TOKEN_ENDPOINT, AUTHORIZATION_ENDPOINT, ACCESS_TOKEN_ENDPOINT, callback=CALLBACK, server=SERVER, port=PORT)
    
    pause()
    print 'Consumer Key: %s' % consumer.consumer_key
    print 'Consumer Secret: %s' % consumer.consumer_secret
    
    # Obtain a Request Token
    pause()
    print '** Obtain a Request Token ...'
    pause()
    print 'Request:', REQUEST_TOKEN_ENDPOINT
    response = consumer.get_request_token()
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        request_token = consumer.parse_token(response.read())
        print 'Got request token.'
        print 'request token: %s' % request_token.token
        print 'request token secret: %s' % request_token.secret
    else:
        print '%s Error: %s' % (response.status, response.reason)
        print response.read()
        return False
    
    # Request authorization
    pause()
    print '** Request User Authorization ...'
    pause()
    print 'Request:', AUTHORIZATION_ENDPOINT
    print 'Token:', request_token.token
    response = consumer.request_authorization(request_token.token)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        print 'Got login page.'
    else:
        print '%s Error: %s' % (response.status, response.reason)
        print response.read()
        return False
        
    # Obtain an Access Token
    pause()
    print '** Obtain an Access Token ...'
    pause()
    print 'Request:', ACCESS_TOKEN_ENDPOINT
    # use the known request token to avoid storage
    response = consumer.get_access_token(REQUEST_TOKEN, REQUEST_TOKEN_SECRET)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        access_token = consumer.parse_token(response.read())
        print 'Got access token.'
        print 'access token: %s' % access_token.token
        print 'access token secret: %s' % access_token.secret
    else:
        print '%s Error: %s' % (response.status, response.reason)
        print response.read()
        return False
        
    # Access Protected Resources
    pause()
    print '** Access Protected Resources ...'
    pause()
    request_parameters = {'file': 'vacation.jpg', 'size': 'original'}
    print 'Request:', API_ENDPOINT
    response = consumer.oauth_request(API_ENDPOINT, ACCESS_TOKEN, ACCESS_TOKEN_SECRET, oauth_timestamp=ts, oauth_nonce=nonce, request_parameters=request_parameters)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        print 'Protected resources returned.'
    else:
        print '%s Error: %s' % (response.status, response.reason)
        print response.read()
        return False
    
    pause()
'''
        
def pause():
    print ''
    time.sleep(2)

if __name__ == '__main__':
    run_example()
    print 'Done.'