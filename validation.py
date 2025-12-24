import re
from typing import Tuple

ACCOUNT_RE = re.compile(r"^\d{10,12}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")


def validate_username(username: str) -> Tuple[bool, str]:
    if not USERNAME_RE.fullmatch(username or ""):
        return False, "Username must be 3-20 chars: letters/numbers/underscore only."
    return True, "OK"


def validate_account_no(account_no: str) -> Tuple[bool, str]:
    if not ACCOUNT_RE.fullmatch(account_no or ""):
        return False, "Account number must be 10-12 digits."
    return True, "OK"


def validate_amount(amount: float, max_amount: float = 100000.0) -> Tuple[bool, str]:
    try:
        amt = float(amount)
    except (TypeError, ValueError):
        return False, "Amount must be a number."
    if amt <= 0:
        return False, "Amount must be > 0."
    if amt > max_amount:
        return False, f"Amount exceeds max limit {max_amount}."
    return True, "OK"
