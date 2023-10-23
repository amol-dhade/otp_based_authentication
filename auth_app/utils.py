from twilio.rest import Client
from django.core.mail import send_mail
from django.conf import settings

def send_otp_via_sms(phone_number, otp):
    twilio_sid = settings.TWILIO_SID
    auth_token = settings.AUTH_TOKEN
    client = Client(twilio_sid, auth_token)
    from_phone = settings.FROM_PHONE  # Your Twilio phone number
    to_phone = phone_number    # Recipient's phone number
    # Send an SMS
    message = client.messages.create(
        body=f'Your otp for verification is {otp}',
        from_=from_phone,
        to=to_phone
    )
    
def send_password_reset_link_via_email(data):
    subject = data['email_subject']
    message = data['email_body']
    to_email = data['to_email']
    email_from = settings.EMAIL_HOST_USER
    #send mail
    send_mail(subject, message, email_from, [to_email]) 
