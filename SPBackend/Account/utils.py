from django.core.mail import EmailMessage
import os

class Util:
    @staticmethod
    def send_email(data):
        # print(data)
        email = EmailMessage(
            subject=data['subject'],
            body=data['body'],
            from_email=data['from_email'],
            to=[data['to_email']],
            # fail_silently=False,
        )
        email.content_subtype = "html"
        email.send()
        #  email.send(fail_silently=False)
        # print(email.from_email)
        # print(email.to)