import time
import pickle
from oauth import consumer

SERVER = 'localhost'
PORT = 8080

CONSUMER_KEY = '1b20acc6'
CONSUMER_SECRET = '427a5979d9df7722'

'''print '*** Web Consumer Application ***'
consumer = consumer.OAuthWebConsumer(CONSUMER_KEY, CONSUMER_SECRET, server=SERVER, port=PORT)

# Request authorization
time.sleep(1)
print ''
print 'requesting authorization...'
http_request_uri = 'http://sp.example.com/oauth/authorize'
response = consumer.request_authorization(http_request_uri, token.token)
time.sleep(2)
print 'Response status: %s' % response.status
print 'Got login page'
'''

print '*** Desktop Consumer Application ***'
consumer = consumer.OAuthDesktopConsumer(CONSUMER_KEY, CONSUMER_SECRET, server=SERVER, port=PORT)

# Request a single-use token
time.sleep(1)
print ''
print 'requesting single-use token...'
http_request_uri = 'http://sp.example.com/oauth/get_su_token'
nonce = consumer.generate_nonce()
ts = consumer.generate_timestamp()
token = None
response = consumer.get_single_use_token(http_request_uri, nonce, ts)
time.sleep(2)
print 'Response status: %s' % response.status
if response.status == 200:
    print 'Got single-use token for desktop app.'
    token = pickle.loads(response.read())
    print 'token: %s' % token.token
    print 'secret: %s' % token.secret
else:
    print '%s Error: %s' % (response.status, response.reason)

# Request authorization
if token:
    time.sleep(1)
    print ''
    print 'requesting authorization...'
    http_request_uri = 'http://sp.example.com/oauth/authorize'
    response = consumer.request_authorization(http_request_uri, token.token)
    time.sleep(2)
    print 'Response status: %s' % response.status
    print 'Got login page'




