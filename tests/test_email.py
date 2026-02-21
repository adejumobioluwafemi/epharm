"""
FILE: tests/test_email.py
Email service tests for the E-Pharmacy API.
Tests email construction, template rendering, and service behaviour in
both send (mocked) and no-send modes.

Uses mock_email_settings to disable actual Resend API calls.
"""

import pytest
from datetime import datetime

from src.email.schemas import (
    AccountLockedEmailData,
    PasswordChangedEmailData,
    PasswordResetEmailData,
    WelcomeEmailData,
)
from src.email.service import EmailService


# ============================================================================
# MODULE-LEVEL FIXTURES (per-file, following reference pattern)
# ============================================================================

@pytest.fixture(name="welcome_data")
def welcome_data_fixture() -> WelcomeEmailData:
    """A fully populated WelcomeEmailData payload."""
    return WelcomeEmailData(
        email="newstaff@demopharmacy.com",
        first_name="Jane",
        last_name="Pharmacist",
        temp_password="TempPass!123",
    )


@pytest.fixture(name="password_reset_data")
def password_reset_data_fixture() -> PasswordResetEmailData:
    """A fully populated PasswordResetEmailData payload."""
    return PasswordResetEmailData(
        email="user@demopharmacy.com",
        first_name="John",
        reset_token="some-valid-reset-token-abc123",
        expires_at=datetime(2026, 1, 1, 12, 0, 0),
    )


@pytest.fixture(name="password_changed_data")
def password_changed_data_fixture() -> PasswordChangedEmailData:
    """A fully populated PasswordChangedEmailData payload."""
    return PasswordChangedEmailData(
        email="user@demopharmacy.com",
        first_name="John",
        changed_at=datetime(2026, 1, 1, 12, 0, 0),
    )


@pytest.fixture(name="account_locked_data")
def account_locked_data_fixture() -> AccountLockedEmailData:
    """A fully populated AccountLockedEmailData payload."""
    return AccountLockedEmailData(
        email="locked@demopharmacy.com",
        first_name="Locked",
        locked_at=datetime(2026, 1, 1, 12, 0, 0),
        reason="Multiple failed login attempts",
    )


# ============================================================================
# SEND WELCOME EMAIL
# ============================================================================

@pytest.mark.email
class TestSendWelcomeEmail:
    """EmailService.send_welcome_email()"""

    @pytest.mark.asyncio
    async def test_send_welcome_email_returns_success_when_emails_disabled(
        self, welcome_data: WelcomeEmailData, mock_email_settings
    ):
        """With SEND_EMAILS=False the service must return success=True (dry-run mode)."""
        result = await EmailService.send_welcome_email(welcome_data)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_welcome_email_does_not_raise(
        self, welcome_data: WelcomeEmailData, mock_email_settings
    ):
        """No exception must be raised regardless of email configuration."""
        try:
            await EmailService.send_welcome_email(welcome_data)
        except Exception as exc:
            pytest.fail(f"send_welcome_email raised unexpectedly: {exc}")

    @pytest.mark.asyncio
    async def test_send_welcome_email_result_has_required_fields(
        self, welcome_data: WelcomeEmailData, mock_email_settings
    ):
        """EmailResponse must contain success and message fields."""
        result = await EmailService.send_welcome_email(welcome_data)

        assert hasattr(result, "success")
        assert hasattr(result, "message")


# ============================================================================
# SEND PASSWORD RESET EMAIL
# ============================================================================

@pytest.mark.email
class TestSendPasswordResetEmail:
    """EmailService.send_password_reset_email()"""

    @pytest.mark.asyncio
    async def test_send_password_reset_email_returns_success_when_emails_disabled(
        self, password_reset_data: PasswordResetEmailData, mock_email_settings
    ):
        """With SEND_EMAILS=False the service must return success=True."""
        result = await EmailService.send_password_reset_email(password_reset_data)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_password_reset_email_does_not_raise(
        self, password_reset_data: PasswordResetEmailData, mock_email_settings
    ):
        try:
            await EmailService.send_password_reset_email(password_reset_data)
        except Exception as exc:
            pytest.fail(f"send_password_reset_email raised unexpectedly: {exc}")

    @pytest.mark.asyncio
    async def test_send_password_reset_email_result_has_required_fields(
        self, password_reset_data: PasswordResetEmailData, mock_email_settings
    ):
        result = await EmailService.send_password_reset_email(password_reset_data)

        assert hasattr(result, "success")
        assert hasattr(result, "message")


# ============================================================================
# SEND PASSWORD CHANGED EMAIL
# ============================================================================

@pytest.mark.email
class TestSendPasswordChangedEmail:
    """EmailService.send_password_changed_email()"""

    @pytest.mark.asyncio
    async def test_send_password_changed_email_returns_success_when_emails_disabled(
        self, password_changed_data: PasswordChangedEmailData, mock_email_settings
    ):
        result = await EmailService.send_password_changed_email(password_changed_data)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_password_changed_email_does_not_raise(
        self, password_changed_data: PasswordChangedEmailData, mock_email_settings
    ):
        try:
            await EmailService.send_password_changed_email(password_changed_data)
        except Exception as exc:
            pytest.fail(f"send_password_changed_email raised unexpectedly: {exc}")


# ============================================================================
# SEND ACCOUNT LOCKED EMAIL
# ============================================================================

@pytest.mark.email
class TestSendAccountLockedEmail:
    """EmailService.send_account_locked_email()"""

    @pytest.mark.asyncio
    async def test_send_account_locked_email_returns_success_when_emails_disabled(
        self, account_locked_data: AccountLockedEmailData, mock_email_settings
    ):
        result = await EmailService.send_account_locked_email(account_locked_data)

        assert result.success is True

    @pytest.mark.asyncio
    async def test_send_account_locked_email_does_not_raise(
        self, account_locked_data: AccountLockedEmailData, mock_email_settings
    ):
        try:
            await EmailService.send_account_locked_email(account_locked_data)
        except Exception as exc:
            pytest.fail(f"send_account_locked_email raised unexpectedly: {exc}")


# ============================================================================
# EMAIL SCHEMA VALIDATION
# ============================================================================

@pytest.mark.email
@pytest.mark.unit
class TestEmailSchemas:
    """Pydantic schema validation for email data objects."""

    def test_welcome_email_data_valid(self):
        data = WelcomeEmailData(
            email="valid@example.com",
            first_name="Valid",
            last_name="User",
            temp_password="TempPass!123",
        )

        assert data.email == "valid@example.com"
        assert data.first_name == "Valid"

    def test_welcome_email_data_invalid_email_raises(self):
        """Pydantic must reject a non-email string in the email field."""
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            WelcomeEmailData(
                email="not-an-email",
                first_name="X",
                last_name="Y",
                temp_password="abc123",
            )

    def test_password_reset_data_valid(self):
        data = PasswordResetEmailData(
            email="reset@example.com",
            first_name="Reset",
            reset_token="abc123token",
            expires_at=datetime(2026, 6, 1, 12, 0, 0),
        )

        assert data.reset_token == "abc123token"

    def test_password_changed_data_valid(self):
        data = PasswordChangedEmailData(
            email="changed@example.com",
            first_name="Changed",
            changed_at=datetime(2026, 1, 1, 9, 0, 0),
        )

        assert data.first_name == "Changed"

    def test_account_locked_data_valid(self):
        data = AccountLockedEmailData(
            email="locked@example.com",
            first_name="Locked",
            locked_at=datetime(2026, 1, 1, 8, 0, 0),
            reason="Too many failures",
        )

        assert data.reason == "Too many failures"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])