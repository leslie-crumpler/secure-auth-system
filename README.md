# Secure Authentication System

A Flask-based authentication system demonstrating secure password storage, login validation, brute-force protection, and security logging — aligned with STIG-compliant secure coding practices.

## Features

- Secure password hashing (Werkzeug / bcrypt-style)
- Login attempt rate limiting (brute-force protection)
- Input validation and sanitization
- Failed login logging with timestamps
- Session management with logout

## Technologies

- Python 3
- Flask
- SQLite
- Werkzeug

## Project Structure

```
secure-auth-system/
├── README.md
├── requirements.txt
├── src/
│   ├── app.py        # Routes
│   ├── auth.py       # Hashing, validation, rate limiting
│   ├── models.py     # User model
│   └── database.py   # DB setup
└── tests/
    └── test_auth.py
```

## Installation

```bash
git clone https://github.com/lcrumpler/secure-auth-system
cd secure-auth-system
pip install -r requirements.txt
python src/app.py
```

## Security Highlights

- Passwords are never stored in plain text
- Failed login attempts are tracked per IP
- Accounts are temporarily locked after 5 failed attempts
- All login events are logged with timestamps

## Author

Leslie Crumpler | [GitHub](https://github.com/lcrumpler)
