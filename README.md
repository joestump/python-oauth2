# Overview

This code was originally forked from [Leah Culver and Andy Smith's oauth.py code](http://github.com/leah/python-oauth/). Some of the tests come from a [fork by Vic Fryzel](http://github.com/shellsage/python-oauth), while a revamped Request class and more tests were merged in from [Mark Paschal's fork](http://github.com/markpasc/python-oauth). A number of notable differences exist between this code and its forefathers:

* 100% unit test coverage.
* The <code>DataStore</code> object has been completely ripped out. While creating unit tests for the library I found several substantial bugs with the implementation and confirmed with Andy Smith that it was never fully baked.
* Classes are no longer prefixed with <code>OAuth</code>.
* The <code>Request</code> class now extends from <code>dict</code>.
* The library is likely no longer compatible with Python 2.3.

# Signing a Request

<pre><code>
import oauth
import time

# Set the API endpoint 
url = "http://example.com/photos"

# Set the base oauth_* parameters along with any other parameters required
# for the API call.
params = {
    'oauth_version': "1.0",
    'oauth_nonce': oauth.generate_nonce(),
    'oauth_timestamp': int(time.time())
    'user': 'joestump',
    'photoid': 555555555555
}

# Set up instances of our Token and Consumer. The Consumer.key and 
# Consumer.secret are given to you by the API provider. The Token.key and
# Token.secret is given to you after a three-legged authentication.
token = oauth.Token(key="tok-test-key", secret="tok-test-secret")
consumer = oauth.Consumer(key="con-test-key", secret="con-test-secret")

# Set our token/key parameters
params['oauth_token'] = tok.key
params['oauth_consumer_key'] = con.key

# Create our request. Change method, etc. accordingly.
req = oauth.Request(method="GET", url=url, parameters=params)

# Sign the request.
signature_method = oauth.SignatureMethod_HMAC_SHA1()
req.sign_request(signature_method, consumer, token)
</code></pre>
