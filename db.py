# =========================
# db.py
# =========================
# This module is responsible for ALL database interactions.
#
# VERY IMPORTANT DESIGN DECISION:
# -------------------------------
# This is the ONLY file in the project that contains SQL statements.
#
# WHY THIS MATTERS:
# - Prevents SQL injection mistakes
# - Keeps authentication and business logic clean
# - Makes security auditing easier
#
# Other modules (auth.py, banking.py, app.py) NEVER write SQL directly.
# They call functions from this file instead.


import sqlite3
# sqlite3 is a lightweight embedded database.
# It requires no external server and is ideal for secure prototypes and coursework.

from typing import Optional, Tuple
# Used for type hints to make function behavior clear during discussion.


DB_FILE = "bank.db"
# Name of the SQLite database file.
# It is stored locally in the project directory.


# -------------------------
# DATABASE CONNECTION
# -------------------------

def get_conn():
    """
    Creates and returns a new database connection.

    WHY THIS FUNCTION EXISTS:
    -------------------------
    - Centralizes database connection creation
    - Makes it easy to change DB settings in one place
    - Avoids duplicating connection code everywhere
    """
    return sqlite3.connect(DB_FILE)


# -------------------------
# DATABASE INITIALIZATION
# -------------------------

def init_db():
    """
    Initializes all database tables if they do not already exist.
-
    WHY THIS IS IMPORTANT:
    ---------------------
    - Allows the application to run from a clean environment
    - No manual database setup required
    - Ensures consistent schema every time the program starts
    """

    conn = get_conn()
    cur = conn.cursor()

    # -------------------------
    # USERS TABLE
    # -------------------------
    # Stores authentication-related data.
    #
    # SECURITY DESIGN:
    # - Passwords are NOT stored
    # - Only hashed passwords and salts are stored
    # - failed_attempts + locked support brute-force protection
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        pwd_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        failed_attempts INTEGER NOT NULL DEFAULT 0,
        locked INTEGER NOT NULL DEFAULT 0
    )
    """)

    # -------------------------
    # SESSIONS TABLE
    # -------------------------
    # Stores active login sessions.
    #
    # DESIGN IDEA:
    # - Token-based authentication
    # - Each token maps to a username
    # - expiry_ts enforces session expiration
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        expiry_ts INTEGER NOT NULL,
        FOREIGN KEY(username) REFERENCES users(username)
    )
    """)

    # -------------------------
    # ACCOUNTS TABLE
    # -------------------------
    # Stores bank account data.
    #
    # SECURITY DESIGN:
    # - Each account belongs to exactly one user
    # - Ownership is enforced in banking logic
    cur.execute("""
    CREATE TABLE IF NOT EXISTS accounts (
        account_no TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        balance REAL NOT NULL DEFAULT 0,
        FOREIGN KEY(username) REFERENCES users(username)
    )
    """)

    # -------------------------
    # AUDIT LOGS TABLE
    # -------------------------
    # Stores security-relevant events.
    #
    # WHY AUDIT LOGS MATTER:
    # - Non-repudiation (who did what, when)
    # - Security monitoring
    # - Incident investigation
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        username TEXT,
        action TEXT NOT NULL,
        result TEXT NOT NULL,
        details TEXT
    )
    """)

    conn.commit()   # Save schema changes
    conn.close()    # Release DB file lock (important on Windows)


# -------------------------
# USER FUNCTIONS
# -------------------------

def user_get(username: str) -> Optional[Tuple]:
    """
    Fetches a user record by username.

    RETURNS:
    --------
    (username, pwd_hash, salt, failed_attempts, locked)
    or None if the user does not exist.

    SECURITY NOTE:
    --------------
    Uses parameterized SQL to prevent SQL injection.
    """

    conn = get_conn()
    cur = conn.cursor()

    # Parameterized query ensures username is treated as data, not SQL.
    cur.execute(
        "SELECT username, pwd_hash, salt, failed_attempts, locked FROM users WHERE username=?",
        (username,)
    )

    row = cur.fetchone()
    conn.close()
    return row


def user_create(username: str, pwd_hash: bytes, salt: bytes) -> None:
    """
    Inserts a new user into the database.

    SECURITY DESIGN:
    ----------------
    - Stores only hashed password and salt
    - failed_attempts initialized to 0
    - locked initialized to 0 (unlocked)
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO users(username, pwd_hash, salt, failed_attempts, locked) VALUES(?,?,?,?,?)",
        (username, pwd_hash, salt, 0, 0)
    )

    conn.commit()
    conn.close()


def user_set_failed(username: str, failed_attempts: int, locked: int) -> None:
    """
    Updates failed login attempts and lock status.

    WHY THIS EXISTS:
    ----------------
    - Tracks brute-force attempts
    - Allows account lockout enforcement
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "UPDATE users SET failed_attempts=?, locked=? WHERE username=?",
        (failed_attempts, locked, username)
    )

    conn.commit()
    conn.close()


# -------------------------
# SESSION FUNCTIONS
# -------------------------

def session_create(token: str, username: str, expiry_ts: int) -> None:
    """
    Creates a new session entry.

    DESIGN IDEA:
    ------------
    - Token represents authenticated session
    - expiry_ts enforces session timeout
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO sessions(token, username, expiry_ts) VALUES(?,?,?)",
        (token, username, expiry_ts)
    )

    conn.commit()
    conn.close()


def session_get(token: str) -> Optional[Tuple]:
    """
    Retrieves a session by token.

    RETURNS:
    --------
    (token, username, expiry_ts) or None if not found.
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT token, username, expiry_ts FROM sessions WHERE token=?",
        (token,)
    )

    row = cur.fetchone()
    conn.close()
    return row


def session_delete(token: str) -> None:
    """
    Deletes a session.

    WHY THIS IS IMPORTANT:
    ---------------------
    - Used during logout
    - Used when a session expires
    - Prevents token reuse
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("DELETE FROM sessions WHERE token=?", (token,))

    conn.commit()
    conn.close()


# -------------------------
# ACCOUNT FUNCTIONS
# -------------------------

def account_create(account_no: str, username: str, balance: float) -> None:
    """
    Creates a new bank account.

    SECURITY NOTE:
    --------------
    - Ownership is linked to username
    - Authorization is enforced in banking.py
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO accounts(account_no, username, balance) VALUES(?,?,?)",
        (account_no, username, balance)
    )

    conn.commit()
    conn.close()


def account_get(account_no: str) -> Optional[Tuple]:
    """
    Retrieves account details.

    RETURNS:
    --------
    (account_no, username, balance) or None if not found.
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "SELECT account_no, username, balance FROM accounts WHERE account_no=?",
        (account_no,)
    )

    row = cur.fetchone()
    conn.close()
    return row


def account_update_balance(account_no: str, new_balance: float) -> None:
    """
    Updates account balance.

    SECURITY DESIGN:
    ----------------
    - Used only after validation and authorization
    - Prevents direct user manipulation
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "UPDATE accounts SET balance=? WHERE account_no=?",
        (new_balance, account_no)
    )

    conn.commit()
    conn.close()


# -------------------------
# AUDIT LOGGING
# -------------------------

def audit_log(ts: int, username: str, action: str, result: str, details: str = "") -> None:
    """
    Inserts an audit log entry.

    WHY AUDIT LOGGING MATTERS:
    -------------------------
    - Enables non-repudiation
    - Tracks security-sensitive events
    - Supports forensic analysis
    """

    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO audit_logs(ts, username, action, result, details) VALUES(?,?,?,?,?)",
        (ts, username, action, result, details)
    )

    conn.commit()
    conn.close()
