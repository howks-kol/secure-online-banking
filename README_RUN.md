# Secure Online Banking Mini System (Runnable Prototype)

## Project Overview
This project is a secure online banking mini-system prototype built for a Secure Systems Design course.  
It demonstrates key security practices such as:

- Secure user authentication with PBKDF2 password hashing + salt
- Brute-force protection using account lockout
- Token-based session management with expiration
- Input validation (username, account number, transfer amount)
- SQLite database persistence (users, sessions, accounts, audit logs)
- AES-256 encryption/decryption using OpenSSL (Bonus)
- Audit logging for security-sensitive actions
- Automated security tests (8 tests)

The prototype is implemented as a Command Line Interface (CLI) to keep focus on security mechanisms rather than UI development.

---

## Team Members
| Name | Student ID |

| Ziad Mohamed Taha | 232007554 |
| Mahmoud Al Shaarawy | 221007606 |
| Abdallah Ewais | 221006269 |

---

## Requirements
- **Python 3.10+** (Tested on Python 3.13.9)
- **OpenSSL installed and accessible from terminal**
  - Windows: OpenSSL must usually be installed manually
  - macOS/Linux: often available by default

Check versions:
```powershell
python --version
openssl version
