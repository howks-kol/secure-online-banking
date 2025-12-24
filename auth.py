# =========================
# auth.py
# =========================
# This module is responsible for AUTHENTICATION and SESSION MANAGEMENT.
# It answers the questions:
#   - Who is the user?
#   - Are their credentials valid?
#   - Should access be granted or denied?
#
# IMPORTANT DESIGN DECISION:
# --------------------------
# This file contains ALL security-sensitive authentication logic.
# It deliberately contains:
#   - NO UI code
#   - NO raw SQL queries
#
# This separation reduces attack surface and makes the code easier to audit.


import hashlib
# hashlib provides cryptographic hash functions.
# We use it for PBKDF2-HMAC, which is designed specifically for password hashing.

import hmac
# hmac provides constant-time comparison.
# This prevents timing attacks when comparing password hashes.

import secrets
# secrets is used instead of random.
# It provides cryptographically secure randomness for salts and session tokens.

import time
# time is used to:
#   - timestamp audit logs
#   - enforce session expiration (token TTL)

from typing import Tuple, Optional
# Tuple and Optional are used for type hints.
# They improve readability and help during discussion and debugging.

import db
# db is the database access layer.
# All SQL is isolated in db.py to prevent SQL injection mistakes.

from validation import validate_username
# Username validation rules are centralized in validation.py.
# This ensures consistency across the entire system.


# -------------------------
# SECURITY POLICY CONSTANTS
# -------------------------

MAX_FAILED = 3
# Maximum number of failed login attempts before account lockout.
# This mitigates brute-force password attacks.

SESSION_TTL_SECONDS = 30 * 60
# Session Time-To-Live (TTL) in seconds.
# Tokens expire after 30 minutes to reduce session hijacking risk.


# -------------------------
# INTERNAL PASSWORD HASHING
# -------------------------

def _hash_password_pbkdf2(password: str, salt: bytes) -> bytes:
    """
    Hashes a password using PBKDF2-HMAC-SHA256.

    WHY THIS EXISTS:
    ----------------
    - Passwords must NEVER be stored in plaintext.
    - Passwords must NOT be encrypted (encryption is reversible).
    - Hashing is one-way and safer for credential storage.

    WHY PBKDF2:
    -----------
    - Designed for password hashing
    - Intentionally slow (resists brute-force attacks)
    - Uses a salt to prevent rainbow table attacks
    """

    return hashlib.pbkdf2_hmac(
        "sha256",                 # Cryptographic hash function
        password.encode("utf-8"), # Convert password string to bytes
        salt,                     # Per-user random salt
        200_000                   # High iteration count (security vs performance tradeoff)
    )


# -------------------------
# USER REGISTRATION
# -------------------------

def register(username: str, password: str) -> Tuple[bool, str]:
    """
    Registers a new user securely.

    RETURNS:
    --------
    (success: bool, message: str)
    """

    # Step 1: Validate username format using allow-list rules.
    # This prevents malformed or malicious usernames.
    ok, msg = validate_username(username)
    if not ok:
        return False, msg

    # Step 2: Check if the username already exists.
    # Prevents overwriting accounts or ambiguity.
    if db.user_get(username) is not None:
        return False, "Username already exists."

    # Step 3: Enforce password policy.
    # Weak passwords are rejected early.
    if password is None or len(password) < 8:
        return False, "Password must be at least 8 characters."

    # Step 4: Generate a cryptographically secure random salt.
    # The salt is UNIQUE per user and stored in the database.
    salt = secrets.token_bytes(16)

    # Step 5: Hash the password with PBKDF2 using the generated salt.
    pwd_hash = _hash_password_pbkdf2(password, salt)

    # Step 6: Store ONLY the hash and salt.
    # The plaintext password is NEVER stored.
    db.user_create(username, pwd_hash, salt)

    # Step 7: Log registration for audit and non-repudiation.
    db.audit_log(int(time.time()), username, "REGISTER", "SUCCESS", "")

    return True, "Registered successfully."


# -------------------------
# USER LOGIN
# -------------------------

def login(username: str, password: str) -> Tuple[bool, str, Optional[str]]:
    """
    Authenticates a user and creates a session token.

    RETURNS:
    --------
    (success: bool, message: str, token: Optional[str])
    """

    # Step 1: Fetch user record from database.
    user = db.user_get(username)

    # If user does not exist, return generic error.
    # This prevents username enumeration attacks.
    if user is None:
        db.audit_log(int(time.time()), username, "LOGIN", "FAIL", "unknown_user")
        return False, "Invalid credentials.", None

    # Unpack stored user data.
    _, pwd_hash, salt, failed_attempts, locked = user

    # Step 2: Check if account is locked.
    # Locked accounts cannot be logged into.
    if locked == 1:
        db.audit_log(int(time.time()), username, "LOGIN", "FAIL", "locked")
        return False, "Account is locked.", None

    # Step 3: Hash the entered password using the stored salt.
    candidate = _hash_password_pbkdf2(password, salt)

    # Step 4: Compare hashes using constant-time comparison.
    # This prevents timing-based side-channel attacks.
    if hmac.compare_digest(candidate, pwd_hash):

        # Reset failed attempts after successful login.
        db.user_set_failed(username, 0, 0)

        # Generate a secure random session token.
        token = secrets.token_urlsafe(32)

        # Calculate token expiration time.
        expiry = int(time.time()) + SESSION_TTL_SECONDS

        # Store the session token in the database.
        db.session_create(token, username, expiry)

        # Log successful login.
        db.audit_log(int(time.time()), username, "LOGIN", "SUCCESS", "")

        return True, "Login successful.", token

    # Step 5: Handle failed password attempt.
    failed_attempts += 1

    # Lock account if maximum failures reached.
    locked_now = 1 if failed_attempts >= MAX_FAILED else 0

    # Update failure count and lock status.
    db.user_set_failed(username, failed_attempts, locked_now)

    # Log failed login attempt.
    db.audit_log(
        int(time.time()),
        username,
        "LOGIN",
        "FAIL",
        f"bad_password attempts={failed_attempts}"
    )

    if locked_now:
        return False, "Account locked due to repeated failures.", None

    return False, "Invalid credentials.", None


# -------------------------
# SESSION VALIDATION
# -------------------------

def require_token(token: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates a session token before allowing protected actions.
    """

    # Token must be present.
    if not token:
        return False, "Missing token.", None

    # Look up token in database.
    session = db.session_get(token)
    if session is None:
        return False, "Invalid token.", None

    # Unpack session data.
    _, username, expiry_ts = session

    # Check for expiration.
    if int(time.time()) > expiry_ts:
        db.session_delete(token)
        db.audit_log(int(time.time()), username, "SESSION", "EXPIRED", "")
        return False, "Token expired.", None

    # Token is valid and active.
    return True, "OK", username


# -------------------------
# LOGOUT
# -------------------------

def logout(token: str) -> Tuple[bool, str]:
    """
    Logs out the user by invalidating the session token.
    """

    # Validate token before logout (ensures correct logging).
    ok, msg, username = require_token(token)
    if not ok:
        return False, msg

    # Remove session from database.
    db.session_delete(token)

    # Log logout event.
    db.audit_log(int(time.time()), username, "LOGOUT", "SUCCESS", "")

    return True, "Logged out."
