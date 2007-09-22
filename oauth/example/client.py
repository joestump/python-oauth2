'''
Example consumer.
'''

import time
import pickle
from oauth.consumer import OAuthConsumer

SERVER = 'localhost'
PORT = 8080
CALLBACK_URL = 'http://printer.example.com/request_token_ready'

# example from the Appendix A
CONSUMER_KEY = 'dpf43f3p2l4k3l03'
CONSUMER_SECRET = 'kd94hf93k423kf44'

# service provider endpoint urls
REQUEST_TOKEN_ENDPOINT = 'https://photos.example.net/request_token'
AUTHORIZATION_ENDPOINT = 'https://photos.example.net/authorize'
ACCESS_TOKEN_ENDPOINT = 'https://photos.example.net/access_token'
API_ENDPOINT = 'http://photos.example.net/photos'
    
def run_example():

    print '*** OAuth Example ***'
    consumer = OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET, server=SERVER, port=PORT)
    
    pause()
    print 'Consumer Key: %s' % consumer.consumer_key
    print 'Consumer Secret: %s' % consumer.consumer_secret
    
    # Obtain a Request Token
    pause()
    print '** Obtain a Request Token ...'
    pause()
    nonce, ts = generate_nonce_timestamp(consumer)
    print 'Request:', consumer.get_token_path(REQUEST_TOKEN_ENDPOINT, oauth_callback=CALLBACK_URL, oauth_nonce=nonce, oauth_timestamp=ts)
    response = consumer.get_request_token(REQUEST_TOKEN_ENDPOINT, oauth_callback=CALLBACK_URL, oauth_nonce=nonce, oauth_timestamp=ts)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        request_token = pickle.loads(response.read())
        print 'Got request token.'
        print 'request token: %s' % request_token.token
        print 'request token secret: %s' % request_token.secret
    else:
        print '%s Error: %s' % (response.status, response.reason)
        return False
    
    # Request authorization
    pause()
    print '** Request User Authorization ...'
    pause()
    print 'Request:', consumer.get_authorization_path(AUTHORIZATION_ENDPOINT, request_token.token)
    response = consumer.request_authorization(AUTHORIZATION_ENDPOINT, request_token.token)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        print 'Got login page.'
    else:
        print '%s Error: %s' % (response.status, response.reason)
        return False
        
    # Obtain an Access Token
    pause()
    print '** Obtain an Access Token ...'
    # generate a nonce and timestamp for this request
    pause()
    nonce, ts = generate_nonce_timestamp(consumer)
    print 'Request:', consumer.get_token_path(ACCESS_TOKEN_ENDPOINT, oauth_token=request_token.token, oauth_nonce=nonce, oauth_timestamp=ts)
    response = consumer.get_access_token(ACCESS_TOKEN_ENDPOINT, oauth_token=request_token.token, oauth_nonce=nonce, oauth_timestamp=ts)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        access_token = pickle.loads(response.read())
        print 'Got access token.'
        print 'access token: %s' % access_token.token
        print 'access token secret: %s' % access_token.secret
    else:
        print '%s Error: %s' % (response.status, response.reason)
        return False
        
    # Access Protected Resources
    pause()
    print '** Access Protected Resources ...'
    pause()
    nonce, ts = generate_nonce_timestamp(consumer)
    request_parameters = {'file': 'vacation.jpg', 'size': 'original'}
    print 'Request:', consumer.get_oauth_request_path(API_ENDPOINT, oauth_token=access_token.token, oauth_token_secret=access_token.secret, oauth_timestamp=ts, oauth_nonce=nonce, request_parameters=request_parameters)
    response = consumer.oauth_request(API_ENDPOINT, oauth_token=access_token.token, oauth_token_secret=access_token.secret, oauth_timestamp=ts, oauth_nonce=nonce, request_parameters=request_parameters)
    pause()
    print 'Response: %s' % response.status
    if response.status == 200:
        print 'Protected resources returned.'
    else:
        print '%s Error: %s' % (response.status, response.reason)
        return False
    
    pause()
        
def pause():
    print ''
    time.sleep(2)

def generate_nonce_timestamp(consumer):
    # generate a nonce and timestamp for this request
    return consumer.generate_nonce(), consumer.generate_timestamp()

if __name__ == '__main__':
    run_example()
    print 'Done.'
    





