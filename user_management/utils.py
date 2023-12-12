import jwt

from django.core.mail import EmailMessage
from rest_framework import status
from rest_framework.response import Response
from celery import shared_task


class Utils:
    @staticmethod
    @shared_task(name="send_email")
    def send_email(subject, body, recipients, attachements=None):
        """Send an email to recipients
        subject: subject of the email
        body: body of the email
        recipients: list of recipients

        Optional keyword arguments:
        attachements: list of files to attach to the email

        type: list of dicts with keys:
            - file_name: name of the file
            - content: content of the file
            - type: content type of the file
        """
        email = EmailMessage(
            subject=subject,
            body=body,
            to=recipients,
            from_email=None
        )
        if attachements:
            for attachement in attachements:
                email.attach(
                    attachement["file_name"], attachement["content"],
                    attachement["type"])
        email.content_subtype = 'html'
        email_status = email.send(fail_silently=False)
        return {"email_status": email_status, "result": "success"}

    @staticmethod
    def decode_token(token, jwt_key):
        try:
            return jwt.decode(token, key=jwt_key, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Token Expired'},
                            status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid token'},
                            status=status.HTTP_400_BAD_REQUEST)
