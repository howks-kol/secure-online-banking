import subprocess
import base64


class CryptoError(Exception):
    pass


def encrypt_text_aes256(plaintext: str, passphrase: str) -> str:
    if not passphrase or len(passphrase) < 8:
        raise CryptoError("Passphrase must be at least 8 characters.")

    cmd = [
        "openssl", "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-salt",
        "-base64",
        "-A",
        "-pass", f"pass:{passphrase}"
    ]

    try:
        result = subprocess.run(
            cmd,
            input=plaintext.encode("utf-8"),
            capture_output=True,
            check=True
        )
        return result.stdout.decode("utf-8").strip()

    except subprocess.CalledProcessError as e:
        err = e.stderr.decode("utf-8", errors="ignore").strip()
        raise CryptoError(f"OpenSSL encrypt failed: {err}")


def decrypt_text_aes256(ciphertext_b64: str, passphrase: str) -> str:
    if not passphrase or len(passphrase) < 8:
        raise CryptoError("Passphrase must be at least 8 characters.")

    ciphertext_b64 = ciphertext_b64.strip()

    try:
        base64.b64decode(ciphertext_b64.encode("utf-8"), validate=False)
    except Exception:
        raise CryptoError("Ciphertext is not valid base64.")

    cmd = [
        "openssl", "enc",
        "-d",
        "-aes-256-cbc",
        "-pbkdf2",
        "-salt",
        "-base64",
        "-A",
        "-pass", f"pass:{passphrase}"
    ]

    try:
        result = subprocess.run(
            cmd,
            input=ciphertext_b64.encode("utf-8"),
            capture_output=True,
            check=True
        )
        return result.stdout.decode("utf-8").strip()

    except subprocess.CalledProcessError:
        raise CryptoError("OpenSSL decrypt failed (wrong password or corrupted data).")
