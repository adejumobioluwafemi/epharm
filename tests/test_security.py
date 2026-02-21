"""
FILE: tests/test_security.py
Unit tests for the core security module — bcrypt+salt hashing, JWT
encode/decode, token generation helpers.

These tests have no HTTP client dependency; they call security functions directly.
"""

import time
import pytest
from datetime import timedelta
from uuid import uuid4

from src.core.security import (
    create_access_token,
    create_refresh_token_jwt,
    decode_access_token,
    decode_refresh_token,
    generate_refresh_token,
    generate_reset_token,
    generate_salt,
    generate_temp_password,
    hash_password,
    verify_password,
)
from src.shared.models import RoleName, UserType


# ============================================================================
# SALT GENERATION
# ============================================================================

@pytest.mark.unit
class TestGenerateSalt:
    """generate_salt()"""

    def test_generates_64_char_hex_string(self):
        """Salt must be exactly 64 hex characters (32 bytes)."""
        salt = generate_salt()

        assert isinstance(salt, str)
        assert len(salt) == 64

    def test_each_call_returns_unique_salt(self):
        """Two calls must produce different salts (collision extremely unlikely)."""
        salt1 = generate_salt()
        salt2 = generate_salt()

        assert salt1 != salt2

    def test_salt_contains_only_hex_characters(self):
        """Salt must be a valid hex string."""
        salt = generate_salt()
        int(salt, 16)  # raises ValueError if not valid hex


# ============================================================================
# PASSWORD HASHING
# ============================================================================

@pytest.mark.unit
class TestPasswordHashing:
    """hash_password() and verify_password()"""

    def test_hash_password_returns_non_empty_string(self):
        salt = generate_salt()
        result = hash_password("MyPassword123!", salt)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_verify_password_correct_password_returns_true(self):
        salt = generate_salt()
        plain = "CorrectPassword!"
        hashed = hash_password(plain, salt)

        assert verify_password(plain, salt, hashed) is True

    def test_verify_password_wrong_password_returns_false(self):
        salt = generate_salt()
        hashed = hash_password("RightPassword!", salt)

        assert verify_password("WrongPassword!", salt, hashed) is False

    def test_verify_password_wrong_salt_returns_false(self):
        """Hashing with one salt and verifying with another must fail."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        hashed = hash_password("SomePassword!", salt1)

        assert verify_password("SomePassword!", salt2, hashed) is False

    def test_same_password_different_salts_produce_different_hashes(self):
        """Two users with the same password must have different hashes."""
        plain = "SharedPassword!"
        salt1, salt2 = generate_salt(), generate_salt()
        hash1 = hash_password(plain, salt1)
        hash2 = hash_password(plain, salt2)

        assert hash1 != hash2

    def test_empty_password_can_be_hashed_and_verified(self):
        """Edge case: empty password string must still produce a verifiable hash."""
        salt = generate_salt()
        hashed = hash_password("", salt)

        assert verify_password("", salt, hashed) is True
        assert verify_password("not_empty", salt, hashed) is False


# ============================================================================
# TEMP PASSWORD GENERATION
# ============================================================================

@pytest.mark.unit
class TestGenerateTempPassword:
    """generate_temp_password()"""

    def test_default_length_is_twelve(self):
        pwd = generate_temp_password()
        assert len(pwd) == 12

    def test_custom_length_is_respected(self):
        for length in [8, 16, 24]:
            pwd = generate_temp_password(length=length)
            assert len(pwd) == length

    def test_each_call_produces_unique_password(self):
        """Two temp passwords should essentially never collide."""
        pwd1 = generate_temp_password()
        pwd2 = generate_temp_password()

        assert pwd1 != pwd2


# ============================================================================
# RESET TOKEN GENERATION
# ============================================================================

@pytest.mark.unit
class TestGenerateResetToken:
    """generate_reset_token()"""

    def test_generates_non_empty_url_safe_string(self):
        token = generate_reset_token()

        assert isinstance(token, str)
        assert len(token) > 0

    def test_each_call_returns_unique_token(self):
        t1 = generate_reset_token()
        t2 = generate_reset_token()

        assert t1 != t2

    def test_token_is_url_safe(self):
        """URL-safe tokens must not contain '+' or '/' characters."""
        for _ in range(20):
            token = generate_reset_token()
            assert "+" not in token
            assert "/" not in token


# ============================================================================
# ACCESS TOKEN
# ============================================================================

@pytest.mark.unit
class TestCreateAndDecodeAccessToken:
    """create_access_token() and decode_access_token()"""

    def test_create_and_decode_round_trip(self):
        """Encoding then decoding must return the original payload values."""
        user_id = uuid4()
        email = "user@example.com"
        tenant_id = uuid4()
        store_ids = [uuid4(), uuid4()]
        roles = [RoleName.STORE_MANAGER]

        token = create_access_token(
            user_id=user_id,
            email=email,
            user_type=UserType.STAFF,
            tenant_id=tenant_id,
            store_ids=store_ids,
            roles=roles, # type: ignore
        )
        payload = decode_access_token(token)

        assert payload is not None
        assert payload["sub"] == str(user_id)
        assert payload["email"] == email
        assert payload["tenant_id"] == str(tenant_id)
        assert payload["user_type"] == UserType.STAFF
        assert str(store_ids[0]) in payload["store_ids"]
        assert RoleName.STORE_MANAGER in payload["roles"]

    def test_token_without_tenant_id_decodes_none(self):
        """SUPER_ADMIN tokens have no tenant_id; payload tenant_id must be None."""
        token = create_access_token(
            user_id=uuid4(),
            email="admin@platform.com",
            user_type=UserType.SUPER_ADMIN,
            roles=[RoleName.SUPER_ADMIN],
        )
        payload = decode_access_token(token)

        assert payload["tenant_id"] is None # type: ignore

    def test_token_contains_correct_issuer_and_audience(self):
        """iss and aud claims must match epharm-api / epharm-frontend."""
        token = create_access_token(
            user_id=uuid4(),
            email="x@x.com",
            user_type=UserType.STAFF,
        )
        payload = decode_access_token(token)

        assert payload["iss"] == "epharm-api" # type: ignore
        assert payload["aud"] == "epharm-frontend" # type: ignore

    def test_expired_token_returns_none(self):
        """A token with a negative expiry must be rejected."""
        token = create_access_token(
            user_id=uuid4(),
            email="expired@example.com",
            user_type=UserType.STAFF,
            expires_delta=timedelta(seconds=-1),
        )
        # Allow the token to age slightly
        time.sleep(0.05)
        payload = decode_access_token(token)

        assert payload is None

    def test_tampered_token_returns_none(self):
        """Modifying any character in the token must cause decode to return None."""
        token = create_access_token(
            user_id=uuid4(),
            email="valid@example.com",
            user_type=UserType.STAFF,
        )
        tampered = token[:-3] + "xxx"
        payload = decode_access_token(tampered)

        assert payload is None

    def test_garbage_string_returns_none(self):
        assert decode_access_token("this.is.garbage") is None

    def test_empty_string_returns_none(self):
        assert decode_access_token("") is None


# ============================================================================
# REFRESH TOKEN
# ============================================================================

@pytest.mark.unit
class TestCreateAndDecodeRefreshToken:
    """create_refresh_token_jwt() and decode_refresh_token()"""

    def test_create_and_decode_returns_correct_user_id(self):
        """Encoding then decoding a refresh token must return the original user_id."""
        user_id = uuid4()
        token = create_refresh_token_jwt(user_id=user_id)
        returned_sub = decode_refresh_token(token)

        assert returned_sub == str(user_id)

    def test_refresh_token_payload_has_type_refresh(self):
        """Refresh tokens must include type='refresh' to distinguish from access tokens."""
        from src.core.security import decode_access_token  # reuse — same key/algo
        token = create_refresh_token_jwt(user_id=uuid4())
        payload = decode_access_token(token)

        assert payload["type"] == "refresh" # type: ignore

    def test_expired_refresh_token_returns_none(self):
        """Expired refresh token must be rejected."""
        token = create_refresh_token_jwt(
            user_id=uuid4(),
            expires_delta=timedelta(seconds=-1),
        )
        time.sleep(0.05)
        result = decode_refresh_token(token)

        assert result is None

    def test_access_token_is_rejected_as_refresh_token(self):
        """Using an access token where a refresh token is expected must return None."""
        access_token = create_access_token(
            user_id=uuid4(),
            email="x@x.com",
            user_type=UserType.STAFF,
        )
        result = decode_refresh_token(access_token)

        # Access tokens don't have type='refresh' so must be rejected
        assert result is None

    def test_garbage_refresh_token_returns_none(self):
        assert decode_refresh_token("garbage.token.here") is None

    def test_two_refresh_tokens_for_same_user_are_different(self):
        """Each call must produce a unique token (different iat/exp values)."""
        user_id = uuid4()
        token1 = create_refresh_token_jwt(user_id=user_id)
        time.sleep(0.05)
        token2 = create_refresh_token_jwt(user_id=user_id)

        assert token1 != token2


# ============================================================================
# REFRESH TOKEN VALUE (opaque)
# ============================================================================

@pytest.mark.unit
class TestGenerateRefreshToken:
    """generate_refresh_token() — the opaque random token (not the JWT)."""

    def test_generates_non_empty_string(self):
        token = generate_refresh_token()
        assert isinstance(token, str)
        assert len(token) > 0

    def test_each_call_produces_unique_value(self):
        t1 = generate_refresh_token()
        t2 = generate_refresh_token()
        assert t1 != t2

    def test_token_is_url_safe(self):
        """tokens must not contain '+' or '/' (URL-safe base64)."""
        for _ in range(20):
            token = generate_refresh_token()
            assert "+" not in token
            assert "/" not in token


# ============================================================================
# RUN
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])