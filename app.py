import db
import auth
import banking
from crypto_aes_openssl import encrypt_text_aes256, decrypt_text_aes256, CryptoError


def main():
    db.init_db()
    print("=== Secure Online Banking Mini-System (Runnable CLI) ===")

    token = None

    while True:
        print("\nChoose:")
        print("1) Register")
        print("2) Login")
        print("3) Create Account (requires login)")
        print("4) View Balance (requires login)")
        print("5) Transfer (requires login)")
        print("6) AES Encrypt Text")
        print("7) AES Decrypt Text")
        print("8) Logout")
        print("9) Exit")

        choice = input(">> ").strip()

        if choice == "1":
            u = input("Username: ").strip()
            p = input("Password (min 8 chars): ").strip()
            ok, msg = auth.register(u, p)
            print(msg)

        elif choice == "2":
            u = input("Username: ").strip()
            p = input("Password: ").strip()
            ok, msg, t = auth.login(u, p)
            print(msg)
            if ok:
                token = t
                print("Your token:", token)

        elif choice == "3":
            if not token:
                print("Login required.")
                continue
            ok, msg, username = auth.require_token(token)
            if not ok:
                print(msg)
                token = None
                continue
            acct = input("New account number (10-12 digits): ").strip()
            bal = float(input("Initial balance: ").strip() or "0")
            ok, msg = banking.create_account(username, acct, bal)
            print(msg)

        elif choice == "4":
            if not token:
                print("Login required.")
                continue
            ok, msg, username = auth.require_token(token)
            if not ok:
                print(msg)
                token = None
                continue
            acct = input("Account number: ").strip()
            ok, msg, bal = banking.get_balance(username, acct)
            print(msg)
            if ok:
                print("Balance:", bal)

        elif choice == "5":
            if not token:
                print("Login required.")
                continue
            ok, msg, username = auth.require_token(token)
            if not ok:
                print(msg)
                token = None
                continue
            from_acct = input("From account: ").strip()
            to_acct = input("To account: ").strip()
            amt = float(input("Amount: ").strip())
            ok, msg = banking.transfer(username, from_acct, to_acct, amt)
            print(msg)

        elif choice == "6":
            text = input("Plain text: ")
            pw = input("Passphrase (>=8 chars): ")
            try:
                enc = encrypt_text_aes256(text, pw)
                print("\nEncrypted (base64):\n", enc)
            except CryptoError as e:
                print("Error:", e)

        elif choice == "7":
            enc = input("Ciphertext (base64): ")
            pw = input("Passphrase: ")
            try:
                dec = decrypt_text_aes256(enc, pw)
                print("\nDecrypted:\n", dec)
            except CryptoError as e:
                print("Error:", e)

        elif choice == "8":
            if not token:
                print("No active session.")
                continue
            ok, msg = auth.logout(token)
            print(msg)
            token = None

        elif choice == "9":
            print("Bye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
