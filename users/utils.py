from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator
import pyotp
import qrcode
import base64
from io import BytesIO

def send_verification_email(user, current_site):
    subject = 'Verify your email address'
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    
    verification_link = f"http://{current_site}/verify-email/{uid}/{token}/"
    
    message = render_to_string('email/verification_email.html', {
        'user': user,
        'verification_link': verification_link,
    })
    
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
        html_message=message
    )

def send_password_reset_email(user, current_site):
    subject = 'Reset your password'
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)
    
    reset_link = f"http://{current_site}/reset-password/{uid}/{token}/"
    
    message = render_to_string('email/password_reset_email.html', {
        'user': user,
        'reset_link': reset_link,
    })
    
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [user.email],
        fail_silently=False,
        html_message=message
    )

def generate_2fa_secret():
    return pyotp.random_base32()

def generate_2fa_qr_code(username, secret):
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(username, issuer_name="YourApp")
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    # Create QR code image
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_code_base64 = base64.b64encode(buffered.getvalue()).decode()
    
    return qr_code_base64

def verify_2fa_code(secret, code):
    totp = pyotp.TOTP(secret)
    return totp.verify(code)
