import oauth2
import imaplib

class IMAP4_SSL(imaplib.IMAP4_SSL):
    def authenticate(self, url, consumer, token):
        if consumer is not None and not isinstance(consumer, oauth2.Consumer):
            raise ValueError("Invalid consumer.")

        if token is not None and not isinstance(token, oauth2.Token):
            raise ValueError("Invalid token.")

        imaplib.IMAP4_SSL.authenticate(self, 'XOAUTH',
            lambda x: oauth2.build_xoauth_string(url, consumer, token))

