import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import os
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """
    Email service for sending password reset tokens and notifications.
    Uses SMTP with TLS encryption for secure email delivery.
    """

    def __init__(self):
        # Email configuration from environment variables
        self.smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.sender_email = os.getenv("SENDER_EMAIL", "noreply@communicationltd.com")
        self.sender_password = os.getenv("SENDER_PASSWORD", "")
        self.sender_name = os.getenv("SENDER_NAME", "Communication LTD")
        self.use_tls = os.getenv("USE_TLS", "true").lower() == "true"

    def send_password_reset_email(self, recipient_email: str, reset_token: str) -> bool:
        """
        Send password reset email with SHA-1 token as per project requirements.

        Args:
            recipient_email: Email address to send reset token to
            reset_token: SHA-1 reset token (40 character hex string)

        Returns:
            bool: True if email sent successfully, False otherwise
        """
        try:
            # Create message
            message = MIMEMultipart("alternative")
            message["Subject"] = "Password Reset - Communication LTD"
            message["From"] = f"{self.sender_name} <{self.sender_email}>"
            message["To"] = recipient_email

            # Create HTML and text content
            text_content = f"""
Password Reset Request - Communication LTD

Hello,

We received a request to reset your password for your Communication LTD account.

Your password reset token is: {reset_token}

This token will expire in 15 minutes for security reasons.

To reset your password:
1. Go to the password reset page
2. Enter your email address
3. Enter the token above: {reset_token}  
4. Create your new password

If you didn't request this password reset, please ignore this email.

Best regards,
Communication LTD Support Team
            """

            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Password Reset - Communication LTD</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; background-color: #f8f9fa; }}
        .token {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 18px; text-align: center; margin: 20px 0; }}
        .warning {{ background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 10px; margin: 15px 0; }}
        .footer {{ text-align: center; padding: 20px; color: #6c757d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
            <p>Communication LTD</p>
        </div>

        <div class="content">
            <p>Hello,</p>

            <p>We received a request to reset your password for your Communication LTD account.</p>

            <p><strong>Your password reset token is:</strong></p>
            <div class="token">{reset_token}</div>

            <div class="warning">
                <strong>⏰ Important:</strong> This token will expire in 15 minutes for security reasons.
            </div>

            <p><strong>To reset your password:</strong></p>
            <ol>
                <li>Go to the password reset page</li>
                <li>Enter your email address</li>
                <li>Enter the token: <code>{reset_token}</code></li>
                <li>Create your new password</li>
            </ol>

            <p>If you didn't request this password reset, please ignore this email.</p>
        </div>

        <div class="footer">
            <p>Best regards,<br>Communication LTD Support Team</p>
            <p>This is an automated message, please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
            """

            # Attach parts
            text_part = MIMEText(text_content, "plain")
            html_part = MIMEText(html_content, "html")
            message.attach(text_part)
            message.attach(html_part)

            # Send email
            if self.sender_password:  # Only if password is configured
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls(context=context)
                    server.login(self.sender_email, self.sender_password)
                    server.sendmail(self.sender_email, recipient_email, message.as_string())

                logger.info(f"Password reset email sent successfully to {recipient_email}")
                return True
            else:
                # For development/testing - log the token instead
                logger.info(f"[DEV MODE] Password reset token for {recipient_email}: {reset_token}")
                print(f"🔐 Password reset token for {recipient_email}: {reset_token}")
                return True

        except Exception as e:
            logger.error(f"Failed to send password reset email to {recipient_email}: {e}")
            # In development mode, still log the token for testing
            if not self.sender_password:
                logger.info(f"[DEV MODE] Password reset token for {recipient_email}: {reset_token}")
                print(f"🔐 Password reset token for {recipient_email}: {reset_token}")
            return False

    def send_welcome_email(self, recipient_email: str, username: str) -> bool:
        """
        Send welcome email to new users.

        Args:
            recipient_email: New user's email
            username: New user's username

        Returns:
            bool: True if sent successfully, False otherwise
        """
        try:
            message = MIMEMultipart("alternative")
            message["Subject"] = "Welcome to Communication LTD"
            message["From"] = f"{self.sender_name} <{self.sender_email}>"
            message["To"] = recipient_email

            text_content = f"""
Welcome to Communication LTD!

Hello {username},

Your account has been created successfully!

You can now log in to access our services and manage your internet plans.

Welcome aboard!

Best regards,
Communication LTD Team
            """

            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Welcome to Communication LTD</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #28a745; color: white; padding: 20px; text-align: center; }}
        .content {{ padding: 20px; }}
        .footer {{ text-align: center; padding: 20px; color: #6c757d; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to Communication LTD!</h1>
        </div>

        <div class="content">
            <p>Hello <strong>{username}</strong>,</p>

            <p>Your account has been created successfully!</p>

            <p>You can now log in to access our services and manage your internet plans.</p>

            <p>Welcome aboard! 🎉</p>
        </div>

        <div class="footer">
            <p>Best regards,<br>Communication LTD Team</p>
        </div>
    </div>
</body>
</html>
            """

            text_part = MIMEText(text_content, "plain")
            html_part = MIMEText(html_content, "html")
            message.attach(text_part)
            message.attach(html_part)

            if self.sender_password:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    if self.use_tls:
                        server.starttls(context=context)
                    server.login(self.sender_email, self.sender_password)
                    server.sendmail(self.sender_email, recipient_email, message.as_string())

                logger.info(f"Welcome email sent to {recipient_email}")
                return True
            else:
                logger.info(f"[DEV MODE] Welcome email for {username} ({recipient_email})")
                print(f"📧 Welcome email sent to {username} ({recipient_email})")
                return True

        except Exception as e:
            logger.error(f"Failed to send welcome email to {recipient_email}: {e}")
            return False


# Singleton instance
email_service = EmailService()
