"""
FILE: src/email/service.py
Email service — Resend API, pharmacy-branded templates
"""

import logging
from src.email.config import email_settings
from src.email.schemas import (
    AccountLockedEmailData,
    EmailResponse,
    PasswordChangedEmailData,
    PasswordResetEmailData,
    WelcomeEmailData,
)

logger = logging.getLogger(__name__)

# ─── HTML template helpers ────────────────────────────────────────────────────

_HEADER = """
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">
"""

_FOOTER = """
<div style="text-align:center;padding:20px;color:#999;font-size:12px;">
  <p>© 2026 Ronaex Platform</p>
  <p>This is an automated message — please do not reply.</p>
</div></body></html>
"""


def _banner(title: str, color1: str = "#1a6b3e", color2: str = "#2ecc71") -> str:
    return f"""
<div style="background:linear-gradient(135deg,{color1} 0%,{color2} 100%);
     padding:30px;text-align:center;border-radius:10px 10px 0 0;">
  <h1 style="color:white;margin:0;font-size:26px;">🏥 {title}</h1>
</div>
<div style="background:#f9f9f9;padding:30px;border-radius:0 0 10px 10px;">
"""


def _close_body() -> str:
    return "</div>"


# Email Service 
class EmailService:
    """Email service — all send methods return EmailResponse."""

    @staticmethod
    def _initialize_resend() -> bool:
        if not email_settings.RESEND_API_KEY:
            return False
        try:
            import resend  # type: ignore
            resend.api_key = email_settings.RESEND_API_KEY
            return True
        except ImportError:
            logger.error("resend package not installed")
            return False

    @staticmethod
    def _send(subject: str, to: str, html: str) -> EmailResponse:
        try:
            import resend  # type: ignore
            params = {
                "from": f"{email_settings.MAIL_FROM_NAME} <{email_settings.MAIL_FROM}>",
                "to": [to],
                "subject": subject,
                "html": html,
            }
            response = resend.Emails.send(params)  # type: ignore
            logger.info(f"Email sent to {to} | Resend ID: {response.get('id')}")
            return EmailResponse(success=True, message=f"Email sent to {to}", email_id=response.get("id"))
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return EmailResponse(success=False, message="Email failed", error=str(e))

    # Welcome 

    @staticmethod
    async def send_welcome_email(data: WelcomeEmailData) -> EmailResponse:
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV] Welcome email → {data.email} | pwd: {data.temp_password}")
            return EmailResponse(success=True, message="Dev mode — email not sent")

        if not EmailService._initialize_resend():
            return EmailResponse(success=False, message="Email service not configured", error="Missing API key")

        pharmacy = data.pharmacy_name or "E-Pharmacy Platform"
        html = _HEADER + _banner(f"Welcome to {pharmacy}!") + f"""
<p>Dear <strong>{data.first_name} {data.last_name}</strong>,</p>
<p>Your staff account has been created. You can now access the pharmacy management system.</p>
<div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #1a6b3e;margin:25px 0;">
  <h3 style="margin-top:0;color:#1a6b3e;">Your Login Credentials</h3>
  <p><strong>Email:</strong> {data.email}</p>
  <p><strong>Temporary Password:</strong>
     <code style="background:#f0f0f0;padding:5px 10px;border-radius:4px;">{data.temp_password}</code>
  </p>
</div>
<div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:15px;margin:25px 0;">
  <p style="margin:0;color:#856404;">
    <strong>⚠️ Security Notice:</strong> Please change your password on first login.
  </p>
</div>
<div style="text-align:center;margin:30px 0;">
  <a href="{email_settings.LOGIN_URL}"
     style="background:#1a6b3e;color:white;padding:14px 30px;text-decoration:none;border-radius:6px;font-weight:bold;">
     Login to Your Account
  </a>
</div>
""" + _close_body() + _FOOTER

        return EmailService._send("Welcome to E-Pharmacy — Your Account Details", data.email, html)

    # Password Reset 

    @staticmethod
    async def send_password_reset_email(data: PasswordResetEmailData) -> EmailResponse:
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV] Password reset → {data.email} | token: {data.reset_token}")
            return EmailResponse(success=True, message="Dev mode — email not sent")

        if not EmailService._initialize_resend():
            return EmailResponse(success=False, message="Email service not configured", error="Missing API key")

        reset_link = f"{email_settings.PASSWORD_RESET_URL}?token={data.reset_token}"
        html = _HEADER + _banner("Password Reset Request 🔐", "#c0392b", "#e74c3c") + f"""
<p>Hello <strong>{data.first_name}</strong>,</p>
<p>We received a request to reset your password. Click below to proceed:</p>
<div style="text-align:center;margin:30px 0;">
  <a href="{reset_link}"
     style="background:#c0392b;color:white;padding:14px 30px;text-decoration:none;border-radius:6px;font-weight:bold;">
     Reset My Password
  </a>
</div>
<div style="background:#fff8e1;border:1px solid #ffc107;border-radius:8px;padding:15px;margin:25px 0;">
  <p style="margin:0;color:#856404;">
    <strong>⚠️</strong> This link expires on: <strong>{data.expires_at.strftime('%d %b %Y at %I:%M %p UTC')}</strong><br>
    If you did not request this, please ignore this email.
  </p>
</div>
<p style="font-size:12px;color:#999;">
  If the button doesn't work, copy this link: <br>{reset_link}
</p>
""" + _close_body() + _FOOTER

        return EmailService._send("Password Reset Request — E-Pharmacy", data.email, html)

    # Password Changed 

    @staticmethod
    async def send_password_changed_email(data: PasswordChangedEmailData) -> EmailResponse:
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV] Password changed → {data.email}")
            return EmailResponse(success=True, message="Dev mode — email not sent")

        if not EmailService._initialize_resend():
            return EmailResponse(success=False, message="Email service not configured", error="Missing API key")

        html = _HEADER + _banner("Password Changed ✅", "#1a6b3e", "#27ae60") + f"""
<p>Hello <strong>{data.first_name}</strong>,</p>
<p>Your pharmacy account password was changed on
   <strong>{data.changed_at.strftime('%d %b %Y at %I:%M %p UTC')}</strong>.
</p>
<div style="background:#ffebee;border:1px solid #ef5350;border-radius:8px;padding:15px;margin:25px 0;">
  <p style="margin:0;color:#c62828;">
    <strong>🔒 Didn't make this change?</strong><br>
    Contact your pharmacy administrator immediately.
  </p>
</div>
<div style="text-align:center;margin:30px 0;">
  <a href="{email_settings.LOGIN_URL}"
     style="background:#1a6b3e;color:white;padding:14px 30px;text-decoration:none;border-radius:6px;font-weight:bold;">
     Login to Your Account
  </a>
</div>
""" + _close_body() + _FOOTER

        return EmailService._send("Password Changed — E-Pharmacy", data.email, html)

    # Account Locked 

    @staticmethod
    async def send_account_locked_email(data: AccountLockedEmailData) -> EmailResponse:
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV] Account locked → {data.email}")
            return EmailResponse(success=True, message="Dev mode — email not sent")

        if not EmailService._initialize_resend():
            return EmailResponse(success=False, message="Email service not configured", error="Missing API key")

        html = _HEADER + _banner("Account Locked 🔒", "#e74c3c", "#c0392b") + f"""
<p>Hello <strong>{data.first_name}</strong>,</p>
<p>Your pharmacy account was <strong>locked</strong> for security reasons.</p>
<div style="background:white;padding:20px;border-radius:8px;border-left:4px solid #e74c3c;margin:25px 0;">
  <p><strong>Locked At:</strong> {data.locked_at.strftime('%d %b %Y at %I:%M %p UTC')}</p>
  <p><strong>Reason:</strong> {data.reason}</p>
</div>
<div style="background:#e3f2fd;border-left:4px solid #2196F3;padding:15px;border-radius:4px;margin:25px 0;">
  <h4 style="margin-top:0;color:#1976D2;">🔓 How to Unlock:</h4>
  <ol style="margin:10px 0;padding-left:20px;font-size:14px;">
    <li>Contact your pharmacy store manager or administrator</li>
    <li>Verify your identity</li>
    <li>Your administrator will unlock your account</li>
    <li>You may be asked to reset your password</li>
  </ol>
</div>
<p style="font-size:14px;color:#666;">
  If you did not attempt to log in, please report this immediately to your administrator.
</p>
""" + _close_body() + _FOOTER

        return EmailService._send("Account Locked — Ronaex Security Alert", data.email, html)