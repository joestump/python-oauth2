import oauth2
import smtplib

class SMTP(smtplib.SMTP, oauth2.XOAuth):
    def authenticate(self, url, consumer, token):
        if consumer is not None and not isinstance(consumer, oauth2.Consumer):
            raise ValueError("Invalid consumer.")

        if token is not None and not isinstance(token, oauth2.Token):
            raise ValueError("Invalid token.")

        smtp_conn.docmd('AUTH', 'XOAUTH %s' + \
            base64.b64encode(oauth2.build_xoauth_string(url, consumer, token))

