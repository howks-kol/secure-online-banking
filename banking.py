import time
from typing import Tuple

import db
from validation import validate_account_no, validate_amount


def create_account(username: str, account_no: str, initial_balance: float = 0.0) -> Tuple[bool, str]:
    ok, msg = validate_account_no(account_no)
    if not ok:
        return False, msg

    if db.account_get(account_no) is not None:
        return False, "Account already exists."

    if initial_balance < 0:
        return False, "Initial balance cannot be negative."

    db.account_create(account_no, username, float(initial_balance))
    db.audit_log(int(time.time()), username, "ACCOUNT_CREATE", "SUCCESS", f"account={account_no}")
    return True, "Account created."


def get_balance(username: str, account_no: str) -> Tuple[bool, str, float]:
    ok, msg = validate_account_no(account_no)
    if not ok:
        return False, msg, 0.0

    acct = db.account_get(account_no)
    if acct is None:
        return False, "Account not found.", 0.0

    _, owner, balance = acct
    if owner != username:
        db.audit_log(int(time.time()), username, "BALANCE_VIEW", "DENY", f"account={account_no} owner={owner}")
        return False, "Access denied.", 0.0

    db.audit_log(int(time.time()), username, "BALANCE_VIEW", "SUCCESS", f"account={account_no}")
    return True, "OK", float(balance)


def transfer(username: str, from_acct: str, to_acct: str, amount: float) -> Tuple[bool, str]:
    ok, msg = validate_account_no(from_acct)
    if not ok:
        return False, f"From account invalid: {msg}"
    ok, msg = validate_account_no(to_acct)
    if not ok:
        return False, f"To account invalid: {msg}"
    ok, msg = validate_amount(amount)
    if not ok:
        return False, msg

    src = db.account_get(from_acct)
    dst = db.account_get(to_acct)
    if src is None or dst is None:
        return False, "Source or destination account not found."

    _, src_owner, src_bal = src
    _, _, dst_bal = dst

    if src_owner != username:
        db.audit_log(int(time.time()), username, "TRANSFER", "DENY", f"from={from_acct}")
        return False, "Access denied."

    src_bal = float(src_bal)
    dst_bal = float(dst_bal)
    amt = float(amount)

    if src_bal < amt:
        db.audit_log(int(time.time()), username, "TRANSFER", "FAIL", "insufficient_funds")
        return False, "Insufficient funds."

    # Update balances
    db.account_update_balance(from_acct, src_bal - amt)
    db.account_update_balance(to_acct, dst_bal + amt)

    db.audit_log(int(time.time()), username, "TRANSFER", "SUCCESS", f"{from_acct}->{to_acct} amount={amt}")
    return True, "Transfer successful."
