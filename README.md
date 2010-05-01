# Overview

This code was originally forked from [Leah Culver and Andy Smith's oauth.py code](http://github.com/leah/python-oauth/). Some of the tests come from a [fork by Vic Fryzel](http://github.com/shellsage/python-oauth), while a revamped Request class and more tests were merged in from [Mark Paschal's fork](http://github.com/markpasc/python-oauth). A number of notable differences exist between this code and its forefathers:

* 100% unit test coverage.
* The <code>DataStore</code> object has been completely ripped out. While creating unit tests for the library I found several substantial bugs with the implementation and confirmed with Andy Smith that it was never fully baked.
* Classes are no longer prefixed with <code>OAuth</code>.
* The <code>Request</code> class now extends from <code>dict</code>.
* The library is likely no longer compatible with Python 2.3.
* The <code>Client</code> class works and extends from <code>httplib2</code>. It's a thin wrapper that handles automatically signing any normal HTTP request you might wish to make.

# Signing a Request

    import oauth2 as oauth
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
    params['oauth_token'] = token.key
    params['oauth_consumer_key'] = consumer.key
    
    # Create our request. Change method, etc. accordingly.
    req = oauth.Request(method="GET", url=url, parameters=params)
    
    # Sign the request.
    signature_method = oauth.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, token)

# Using the Client

The <code>oauth2.Client</code> is based on <code>httplib2</code> and works just as you'd expect it to. The only difference is the first two arguments to the constructor are an instance of <code>oauth2.Consumer</code> and <code>oauth2.Token</code> (<code>oauth2.Token</code> is only needed for three-legged requests).

    import oauth2 as oauth
    
    # Create your consumer with the proper key/secret.
    consumer = oauth.Consumer(key="your-twitter-consumer-key", 
        secret="your-twitter-consumer-secret")
    
    # Request token URL for Twitter.
    request_token_url = "http://twitter.com/oauth/request_token"
    
    # Create our client.
    client = oauth.Client(consumer)
    
    # The OAuth Client request works just like httplib2 for the most part.
    resp, content = client.request(request_token_url, "GET")
    print resp
    print content

# Twitter Three-legged OAuth Example

Below is an example of how one would go through a three-legged OAuth flow to
gain access to protected resources on Twitter. This is a simple CLI script, but
can be easily translated to a web application.

    import urlparse
    import oauth2 as oauth
    
    consumer_key = 'my_key_from_twitter'
    consumer_secret = 'my_secret_from_twitter'
    
    request_token_url = 'http://twitter.com/oauth/request_token'
    access_token_url = 'http://twitter.com/oauth/access_token'
    authorize_url = 'http://twitter.com/oauth/authorize'
    
    consumer = oauth.Consumer(consumer_key, consumer_secret)
    client = oauth.Client(consumer)
    
    # Step 1: Get a request token. This is a temporary token that is used for 
    # having the user authorize an access token and to sign the request to obtain 
    # said access token.
    
    resp, content = client.request(request_token_url, "GET")
    if resp['status'] != '200':
        raise Exception("Invalid response %s." % resp['status'])
    
    request_token = dict(urlparse.parse_qsl(content))
    
    print "Request Token:"
    print "    - oauth_token        = %s" % request_token['oauth_token']
    print "    - oauth_token_secret = %s" % request_token['oauth_token_secret']
    print 
    
    # Step 2: Redirect to the provider. Since this is a CLI script we do not 
    # redirect. In a web application you would redirect the user to the URL
    # below.
    
    print "Go to the following link in your browser:"
    print "%s?oauth_token=%s" % (authorize_url, request_token['oauth_token'])
    print 
    
    # After the user has granted access to you, the consumer, the provider will
    # redirect you to whatever URL you have told them to redirect to. You can 
    # usually define this in the oauth_callback argument as well.
    accepted = 'n'
    while accepted.lower() == 'n':
        accepted = raw_input('Have you authorized me? (y/n) ')
    oauth_verifier = raw_input('What is the PIN? ')
    
    # Step 3: Once the consumer has redirected the user back to the oauth_callback
    # URL you can request the access token the user has approved. You use the 
    # request token to sign this request. After this is done you throw away the
    # request token and use the access token returned. You should store this 
    # access token somewhere safe, like a database, for future use.
    token = oauth.Token(request_token['oauth_token'],
        request_token['oauth_token_secret'])
    token.set_verifier(oauth_verifier)
    client = oauth.Client(consumer, token)
    
    resp, content = client.request(access_token_url, "POST")
    access_token = dict(urlparse.parse_qsl(content))
    
    print "Access Token:"
    print "    - oauth_token        = %s" % access_token['oauth_token']
    print "    - oauth_token_secret = %s" % access_token['oauth_token_secret']
    print
    print "You may now access protected resources using the access tokens above." 
    print

# Logging into Django w/ Twitter

Twitter also has the ability to authenticate a user [via an OAuth flow](http://apiwiki.twitter.com/Sign-in-with-Twitter). This
flow is exactly like the three-legged OAuth flow, except you send them to a 
slightly different URL to authorize them. 

In this example we'll look at how you can implement this login flow using 
Django and python-oauth2. 

## Set up a Profile model

You'll need a place to store all of your Twitter OAuth credentials after the
user has logged in. In your app's `models.py` file you should add something
that resembles the following model.

    class Profile(models.Model):
        user = models.ForeignKey(User)
        oauth_token = models.CharField(max_length=200)
        oauth_secret = models.CharField(max_length=200)

## Set up your Django views

### `urls.py`

Your `urls.py` should look something like the following. Basically, you need to
have a login URL, a callback URL that Twitter will redirect your users back to,
and a logout URL.

In this example `^login/` and `twitter_login` will send the user to Twitter to
be logged in, `^login/authenticated/` and `twitter_authenticated` will confirm
the login, create the account if necessary, and log the user into the 
application, and `^logout`/ logs the user out in the `twitter_logout` view.


    from django.conf.urls.defaults import *
    from django.contrib import admin
    from mytwitterapp.views import twitter_login, twitter_logout, \
        twitter_authenticated

    admin.autodiscover()

    urlpatterns = patterns('',
        url(r'^admin/doc/', include('django.contrib.admindocs.urls')),
        url(r'^admin/', include(admin.site.urls)),
        url(r'^login/?$', twitter_login),
        url(r'^logout/?$', twitter_logout),
        url(r'^login/authenticated/?$', twitter_authenticated),
    )

### `views.py`

*NOTE:* The following code was coded for Python 2.4 so some of the libraries 
and code here might need to be updated if you are using Python 2.6+. 

    # Python
    import oauth2 as oauth
    import cgi

    # Django
    from django.shortcuts import render_to_response
    from django.http import HttpResponseRedirect
    from django.conf import settings
    from django.contrib.auth import authenticate, login, logout
    from django.contrib.auth.models import User
    from django.contrib.auth.decorators import login_required

    # Project
    from mytwitterapp.models import Profile

    # It's probably a good idea to put your consumer's OAuth token and
    # OAuth secret into your project's settings. 
    consumer = oauth.Consumer(settings.TWITTER_TOKEN, settings.TWITTER_SECRET)
    client = oauth.Client(consumer)

    request_token_url = 'http://twitter.com/oauth/request_token'
    access_token_url = 'http://twitter.com/oauth/access_token'

    # This is the slightly different URL used to authenticate/authorize.
    authenticate_url = 'http://twitter.com/oauth/authenticate'

    def twitter_login(request):
        # Step 1. Get a request token from Twitter.
        resp, content = client.request(request_token_url, "GET")
        if resp['status'] != '200':
            raise Exception("Invalid response from Twitter.")

        # Step 2. Store the request token in a session for later use.
        request.session['request_token'] = dict(cgi.parse_qsl(content))

        # Step 3. Redirect the user to the authentication URL.
        url = "%s?oauth_token=%s" % (authenticate_url,
            request.session['request_token']['oauth_token'])

        return HttpResponseRedirect(url)

    
    @login_required
    def twitter_logout(request):
        # Log a user out using Django's logout function and redirect them
        # back to the homepage.
        logout(request)
        return HttpResponseRedirect('/')

    def twitter_authenticated(request):
        # Step 1. Use the request token in the session to build a new client.
        token = oauth.Token(request.session['request_token']['oauth_token'],
            request.session['request_token']['oauth_token_secret'])
        client = oauth.Client(consumer, token)
    
        # Step 2. Request the authorized access token from Twitter.
        resp, content = client.request(access_token_url, "GET")
        if resp['status'] != '200':
            print content
            raise Exception("Invalid response from Twitter.")
    
        """
        This is what you'll get back from Twitter. Note that it includes the
        user's user_id and screen_name.
        {
            'oauth_token_secret': 'IcJXPiJh8be3BjDWW50uCY31chyhsMHEhqJVsphC3M',
            'user_id': '120889797', 
            'oauth_token': '120889797-H5zNnM3qE0iFoTTpNEHIz3noL9FKzXiOxwtnyVOD',
            'screen_name': 'heyismysiteup'
        }
        """
        access_token = dict(cgi.parse_qsl(content))
    
        # Step 3. Lookup the user or create them if they don't exist.
        try:
            user = User.objects.get(username=access_token['screen_name'])
        except User.DoesNotExist:
            # When creating the user I just use their screen_name@twitter.com
            # for their email and the oauth_token_secret for their password.
            # These two things will likely never be used. Alternatively, you 
            # can prompt them for their email here. Either way, the password 
            # should never be used.
            user = User.objects.create_user(access_token['screen_name'],
                '%s@twitter.com' % access_token['screen_name'],
                access_token['oauth_token_secret'])
    
            # Save our permanent token and secret for later.
            profile = Profile()
            profile.user = user
            profile.oauth_token = access_token['oauth_token']
            profile.oauth_secret = access_token['oauth_token_secret']
            profile.save()
    
        # Authenticate the user and log them in using Django's pre-built 
        # functions for these things.
        user = authenticate(username=access_token['screen_name'],
            password=access_token['oauth_token_secret'])
        login(request, user)
    
        return HttpResponseRedirect('/')
    

### `settings.py`

* You'll likely want to set `LOGIN_URL` to `/login/` so that users are properly redirected to your Twitter login handler when you use `@login_required` in other parts of your Django app.
* You can also set `AUTH_PROFILE_MODULE = 'mytwitterapp.Profile'` so that you can easily access the Twitter OAuth token/secret for that user using the `User.get_profile()` method in Django.

# XOAUTH for IMAP and SMTP

Gmail supports OAuth over IMAP and SMTP via a standard they call XOAUTH. This allows you to authenticate against Gmail's IMAP and SMTP servers using an OAuth token and secret. It also has the added benefit of allowing you to use vanilla SMTP and IMAP libraries. The `python-oauth2` package provides both IMAP and SMTP libraries that implement XOAUTH and wrap `imaplib.IMAP4_SSL` and `smtplib.SMTP`. This allows you to connect to Gmail with OAuth credentials using standard Python libraries. 

## IMAP

    import oauth2 as oauth
    import oauth2.clients.imap as imaplib

    # Set up your Consumer and Token as per usual. Just like any other
    # three-legged OAuth request.
    consumer = oauth.Consumer('your_consumer_key', 'your_consumer_secret')
    token = oauth.Token('your_users_3_legged_token', 
        'your_users_3_legged_token_secret')

    # Setup the URL according to Google's XOAUTH implementation. Be sure
    # to replace the email here with the appropriate email address that
    # you wish to access.
    url = "https://mail.google.com/mail/b/your_users_email@gmail.com/imap/"

    conn = imaplib.IMAP4_SSL('imap.googlemail.com')
    conn.debug = 4 

    # This is the only thing in the API for impaplib.IMAP4_SSL that has 
    # changed. You now authenticate with the URL, consumer, and token.
    conn.authenticate(url, consumer, token)

    # Once authenticated everything from the impalib.IMAP4_SSL class will 
    # work as per usual without any modification to your code.
    conn.select('INBOX')
    print conn.list()


## SMTP

    import oauth2 as oauth
    import oauth2.clients.smtp as smtplib

    # Set up your Consumer and Token as per usual. Just like any other
    # three-legged OAuth request.
    consumer = oauth.Consumer('your_consumer_key', 'your_consumer_secret')
    token = oauth.Token('your_users_3_legged_token', 
        'your_users_3_legged_token_secret')

    # Setup the URL according to Google's XOAUTH implementation. Be sure
    # to replace the email here with the appropriate email address that
    # you wish to access.
    url = "https://mail.google.com/mail/b/your_users_email@gmail.com/smtp/"

    conn = smtplib.SMTP('smtp.googlemail.com', 587)
    conn.set_debuglevel(True)
    conn.ehlo('test')
    conn.starttls()

    # Again the only thing modified from smtplib.SMTP is the authenticate
    # method, which works identically to the imaplib.IMAP4_SSL method.
    conn.authenticate(url, consumer, token)


