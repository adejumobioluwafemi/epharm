"""
FILE: src/email/service.py
Email service using Resend API 
Aligned with email schemas
"""
import resend
from typing import Optional
from datetime import datetime
from src.email.config import email_settings
from src.email.schemas import (
    EmailResponse,
    WelcomeEmailData,
    PasswordResetEmailData,
    PasswordChangedEmailData,
    AccountLockedEmailData
)
import logging

logger = logging.getLogger(__name__)


class EmailService:
    """Email service using Resend API"""
    
    @staticmethod
    def _initialize_resend():
        """Initialize Resend with API key"""
        if not email_settings.RESEND_API_KEY:
            logger.warning("Resend API key not configured")
            return False
        
        resend.api_key = email_settings.RESEND_API_KEY
        return True
    
    @staticmethod
    async def send_welcome_email(data: WelcomeEmailData) -> EmailResponse:
        """
        Send welcome email to newly registered user
        
        Args:
            data: WelcomeEmailData with user details
            
        Returns:
            EmailResponse with success status
        """
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV MODE] Would send welcome email to: {data.email}")
            logger.info(f"Username: {data.username}, Password: {data.temp_password}")
            return EmailResponse(
                success=True,
                message="Email sending disabled in development mode"
            )
        
        try:
            if not EmailService._initialize_resend():
                return EmailResponse(
                    success=False,
                    message="Email service not configured",
                    error="Resend API key missing"
                )
            
            # Create HTML email content
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to Oyo Agro System! 🎉</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p style="font-size: 16px; margin-bottom: 20px;">Dear <strong>{data.firstname} {data.lastname}</strong>,</p>
        
        <p style="font-size: 16px; margin-bottom: 20px;">
            Your Extension Officer account has been successfully created! You can now access the Oyo State Agricultural Information Management System.
        </p>
        
        <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #667eea; margin: 25px 0;">
            <h3 style="margin-top: 0; color: #667eea;">Your Login Credentials</h3>
            <p style="margin: 10px 0;"><strong>Username:</strong> {data.username}</p>
            <p style="margin: 10px 0;"><strong>Email:</strong> {data.email}</p>
            <p style="margin: 10px 0;"><strong>Temporary Password:</strong> <code style="background: #f0f0f0; padding: 5px 10px; border-radius: 4px; font-size: 14px;">{data.temp_password}</code></p>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 25px 0;">
            <p style="margin: 0; color: #856404;">
                <strong>⚠️ Security Notice:</strong> Please change your password after your first login for security purposes.
            </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{email_settings.LOGIN_URL}" style="display: inline-block; background: #667eea; color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
                Login to Your Account
            </a>
        </div>
        
        <div style="background: #e3f2fd; border-left: 4px solid #2196F3; padding: 15px; border-radius: 4px; margin: 25px 0;">
            <h4 style="margin-top: 0; color: #1976D2;">💡 Getting Started Tips:</h4>
            <ul style="margin: 10px 0; padding-left: 20px;">
                <li>Login with your username or email</li>
                <li>Complete your profile information</li>
            </ul>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            If you have any questions or need assistance, please contact your system administrator.
        </p>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            Best regards,<br>
            <strong>Ronaex System</strong>
        </p>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        <p>© 2026 Ronaex System</p>
        <p>This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
"""
            
            # Send email via Resend
            params = {
                "from": f"{email_settings.MAIL_FROM_NAME} <{email_settings.MAIL_FROM}>",
                "to": [data.email],
                "subject": "Welcome to Ronaex System - Your Account Details",
                "html": html_content,
            }
            
            response = resend.Emails.send(params) # type: ignore
            
            logger.info(f"Welcome email sent successfully to: {data.email}")
            logger.info(f"Resend ID: {response.get('id')}")
            
            return EmailResponse(
                success=True,
                message=f"Welcome email sent to {data.email}",
                email_id=response.get('id')
            )
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {str(e)}")
            return EmailResponse(
                success=False,
                message="Failed to send welcome email",
                error=str(e)
            )
    
    @staticmethod
    async def send_password_reset_email(data: PasswordResetEmailData) -> EmailResponse:
        """
        Send password reset email with token
        
        Args:
            data: PasswordResetEmailData with reset token
            
        Returns:
            EmailResponse with success status
        """
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV MODE] Would send password reset email to: {data.email}")
            logger.info(f"Reset token: {data.reset_token}")
            return EmailResponse(
                success=True,
                message="Email sending disabled in development mode"
            )
        
        try:
            if not EmailService._initialize_resend():
                return EmailResponse(
                    success=False,
                    message="Email service not configured",
                    error="Resend API key missing"
                )
            
            # Create reset link
            reset_link = f"{email_settings.PASSWORD_RESET_URL}?token={data.reset_token}"
            
            # Calculate expiry time
            hours_until_expiry = email_settings.PASSWORD_RESET_TOKEN_EXPIRE_HOURS
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Password Reset Request 🔐</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p style="font-size: 16px; margin-bottom: 20px;">Hello <strong>{data.firstname}</strong>,</p>
        
        <p style="font-size: 16px; margin-bottom: 20px;">
            We received a request to reset your password for your Ronaex System account (<strong>{data.username}</strong>).
        </p>
        
        <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #f5576c; margin: 25px 0;">
            <p style="margin: 0; font-size: 14px; color: #666;">
                Click the button below to reset your password. This link will expire in <strong>{hours_until_expiry} hours</strong>.
            </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_link}" style="display: inline-block; background: #f5576c; color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
                Reset My Password
            </a>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 8px; padding: 15px; margin: 25px 0;">
            <p style="margin: 0; color: #856404; font-size: 14px;">
                <strong>⚠️ Security Tips:</strong>
            </p>
            <ul style="margin: 10px 0; padding-left: 20px; color: #856404; font-size: 14px;">
                <li>If you didn't request this reset, please ignore this email</li>
                <li>Never share your password with anyone</li>
                <li>Use a strong, unique password</li>
            </ul>
        </div>
        
        <div style="background: #f0f0f0; padding: 15px; border-radius: 4px; margin: 25px 0;">
            <p style="margin: 0; font-size: 12px; color: #666;">
                If the button doesn't work, copy and paste this link into your browser:
            </p>
            <p style="margin: 10px 0; word-break: break-all;">
                <a href="{reset_link}" style="color: #667eea; font-size: 12px;">{reset_link}</a>
            </p>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            This link will expire on: <strong>{data.expires_at.strftime('%B %d, %Y at %I:%M %p')}</strong>
        </p>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            Best regards,<br>
            <strong>Ronaex System Team</strong>
        </p>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        <p>© 2026 Ronaex System</p>
        <p>This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
"""
            
            params = {
                "from": f"{email_settings.MAIL_FROM_NAME} <{email_settings.MAIL_FROM}>",
                "to": [data.email],
                "subject": "Password Reset Request - Ronaex System",
                "html": html_content,
            }
            
            response = resend.Emails.send(params) # type: ignore
            
            logger.info(f"Password reset email sent to: {data.email}")
            logger.info(f"Resend ID: {response.get('id')}")
            
            return EmailResponse(
                success=True,
                message=f"Password reset email sent to {data.email}",
                email_id=response.get('id')
            )
            
        except Exception as e:
            logger.error(f"Failed to send password reset email: {str(e)}")
            return EmailResponse(
                success=False,
                message="Failed to send password reset email",
                error=str(e)
            )
    
    @staticmethod
    async def send_password_changed_email(data: PasswordChangedEmailData) -> EmailResponse:
        """
        Send password changed confirmation email
        
        Args:
            data: PasswordChangedEmailData with user details
            
        Returns:
            EmailResponse with success status
        """
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV MODE] Would send password changed email to: {data.email}")
            return EmailResponse(
                success=True,
                message="Email sending disabled in development mode"
            )
        
        try:
            if not EmailService._initialize_resend():
                return EmailResponse(
                    success=False,
                    message="Email service not configured",
                    error="Resend API key missing"
                )
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Password Changed Successfully ✅</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p style="font-size: 16px; margin-bottom: 20px;">Hello <strong>{data.firstname}</strong>,</p>
        
        <p style="font-size: 16px; margin-bottom: 20px;">
            This email confirms that the password for your account (<strong>{data.username}</strong>) was successfully changed.
        </p>
        
        <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #38ef7d; margin: 25px 0;">
            <p style="margin: 0;"><strong>Account:</strong> {data.username}</p>
            <p style="margin: 10px 0 0 0;"><strong>Changed At:</strong> {data.changed_at.strftime('%B %d, %Y at %I:%M %p')}</p>
        </div>
        
        <div style="background: #ffebee; border: 1px solid #ef5350; border-radius: 8px; padding: 15px; margin: 25px 0;">
            <p style="margin: 0; color: #c62828; font-size: 14px;">
                <strong>🔒 Didn't change your password?</strong>
            </p>
            <p style="margin: 10px 0 0 0; color: #c62828; font-size: 14px;">
                If you did not make this change, please contact your system administrator immediately and secure your account.
            </p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{email_settings.LOGIN_URL}" style="display: inline-block; background: #11998e; color: white; padding: 14px 30px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px;">
                Login to Your Account
            </a>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            For your security, we recommend:
        </p>
        <ul style="font-size: 14px; color: #666;">
            <li>Use a unique password for each account</li>
            <li>Enable two-factor authentication when available</li>
            <li>Never share your password with anyone</li>
        </ul>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            Best regards,<br>
            <strong>Ronaex System Team</strong>
        </p>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        <p>© 2026 Ronaex System</p>
        <p>This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
"""
            
            params = {
                "from": f"{email_settings.MAIL_FROM_NAME} <{email_settings.MAIL_FROM}>",
                "to": [data.email],
                "subject": "Password Changed Successfully - Ronaex System",
                "html": html_content,
            }
            
            response = resend.Emails.send(params) # type: ignore
            
            logger.info(f"Password changed email sent to: {data.email}")
            logger.info(f"Resend ID: {response.get('id')}")
            
            return EmailResponse(
                success=True,
                message=f"Password changed email sent to {data.email}",
                email_id=response.get('id')
            )
            
        except Exception as e:
            logger.error(f"Failed to send password changed email: {str(e)}")
            return EmailResponse(
                success=False,
                message="Failed to send password changed email",
                error=str(e)
            )
    
    @staticmethod
    async def send_account_locked_email(data: AccountLockedEmailData) -> EmailResponse:
        """
        Send account locked notification email
        
        Args:
            data: AccountLockedEmailData with lock details
            
        Returns:
            EmailResponse with success status
        """
        if not email_settings.SEND_EMAILS:
            logger.info(f"[DEV MODE] Would send account locked email to: {data.email}")
            return EmailResponse(
                success=True,
                message="Email sending disabled in development mode"
            )
        
        try:
            if not EmailService._initialize_resend():
                return EmailResponse(
                    success=False,
                    message="Email service not configured",
                    error="Resend API key missing"
                )
            
            html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #ee0979 0%, #ff6a00 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Account Locked 🔒</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <p style="font-size: 16px; margin-bottom: 20px;">Hello <strong>{data.firstname}</strong>,</p>
        
        <p style="font-size: 16px; margin-bottom: 20px;">
            Your account (<strong>{data.username}</strong>) has been locked for security reasons.
        </p>
        
        <div style="background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #ff6a00; margin: 25px 0;">
            <p style="margin: 0;"><strong>Account:</strong> {data.username}</p>
            <p style="margin: 10px 0;"><strong>Locked At:</strong> {data.locked_at.strftime('%B %d, %Y at %I:%M %p')}</p>
            <p style="margin: 10px 0 0 0;"><strong>Reason:</strong> {data.reason}</p>
        </div>
        
        <div style="background: #ffebee; border: 1px solid #ef5350; border-radius: 8px; padding: 15px; margin: 25px 0;">
            <p style="margin: 0; color: #c62828; font-size: 14px;">
                <strong>⚠️ Security Notice</strong>
            </p>
            <p style="margin: 10px 0 0 0; color: #c62828; font-size: 14px;">
                If you did not attempt to access your account, please contact your system administrator immediately.
            </p>
        </div>
        
        <div style="background: #e3f2fd; border-left: 4px solid #2196F3; padding: 15px; border-radius: 4px; margin: 25px 0;">
            <h4 style="margin-top: 0; color: #1976D2;">🔓 How to Unlock Your Account:</h4>
            <ol style="margin: 10px 0; padding-left: 20px; font-size: 14px;">
                <li>Contact your system administrator</li>
                <li>Verify your identity</li>
                <li>Your administrator will unlock your account</li>
                <li>You can then reset your password if needed</li>
            </ol>
        </div>
        
        <p style="font-size: 14px; color: #666; margin-top: 30px;">
            For assistance, please contact your system administrator or the IT support team.
        </p>
        
        <p style="font-size: 14px; color: #666; margin-top: 20px;">
            Best regards,<br>
            <strong>Ronaex System Team</strong>
        </p>
    </div>
    
    <div style="text-align: center; padding: 20px; color: #999; font-size: 12px;">
        <p>© 2026 Ronaex System</p>
        <p>This is an automated message, please do not reply to this email.</p>
    </div>
</body>
</html>
"""
            
            params = {
                "from": f"{email_settings.MAIL_FROM_NAME} <{email_settings.MAIL_FROM}>",
                "to": [data.email],
                "subject": "Account Locked - Security Alert",
                "html": html_content,
            }
            
            response = resend.Emails.send(params) # type: ignore
            
            logger.info(f"Account locked email sent to: {data.email}")
            logger.info(f"Resend ID: {response.get('id')}")
            
            return EmailResponse(
                success=True,
                message=f"Account locked email sent to {data.email}",
                email_id=response.get('id')
            )
            
        except Exception as e:
            logger.error(f"Failed to send account locked email: {str(e)}")
            return EmailResponse(
                success=False,
                message="Failed to send account locked email",
                error=str(e)
            )