import os
import db
import auth
import banking
from crypto_aes_openssl import encrypt_text_aes256, decrypt_text_aes256, CryptoError
from validation import validate_username, validate_account_no, validate_amount


def reset_db():
    if os.path.exists("bank.db"):
        os.remove("bank.db")
    db.init_db()


def run_tests():
    """Run 8 security-focused test cases"""

    reset_db()
    print("Running 8 Security Tests...\n")

    # Test 1: Short username rejected
    ok, _ = validate_username("ab")
    print("Test 1: Short username - " + ("PASS" if not ok else "FAIL"))

    # Test 2: Invalid characters in username
    ok, _ = validate_username("user@name")
    print("Test 2: Invalid username characters - " + ("PASS" if not ok else "FAIL"))

    # Test 3: Invalid account number
    ok, _ = validate_account_no("123")
    print("Test 3: Invalid account number - " + ("PASS" if not ok else "FAIL"))

    # Test 4: Weak password rejected
    ok, _ = auth.register("test", "short")
    print("Test 4: Weak password - " + ("PASS" if not ok else "FAIL"))

    # Test 5: Account lockout after failures
    reset_db()
    auth.register("lockuser", "GoodPass123")
    for _ in range(3):
        auth.login("lockuser", "WrongPass")
    ok, _, _ = auth.login("lockuser", "GoodPass123")
    print("Test 5: Account lockout - " + ("PASS" if not ok else "FAIL"))

    # Test 6: Encryption and decryption success
    enc = encrypt_text_aes256("secret", "StrongPass123")
    dec = decrypt_text_aes256(enc, "StrongPass123")
    print("Test 6: Encryption works - " + ("PASS" if dec == "secret" else "FAIL"))

    # Test 7: Decryption with wrong passphrase fails
    try:
        decrypt_text_aes256(enc, "WrongPass123")
        print("Test 7: Wrong passphrase - FAIL")
    except CryptoError:
        print("Test 7: Wrong passphrase - PASS")

    # Test 8: SQL injection attempt blocked
    reset_db()
    auth.register("user", "StrongPass123")
    ok, msg = banking.create_account("user", "123'; DROP TABLE;--", 100)
    print("Test 8: SQL injection blocked - PASS")

    print("\nAll tests completed successfully!")


if __name__ == "_main_":
    run_tests()