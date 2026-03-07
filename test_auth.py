"""
test_auth.py - Tests for secure auth features
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../src"))

from auth import (
    hash_password, verify_password, validate_registration,
    record_failed_attempt, is_locked_out, reset_attempts
)


def test_password_hash():
    h = hash_password("MyPassword1!")
    assert verify_password("MyPassword1!", h) is True
    assert verify_password("wrong", h) is False
    print("PASS: test_password_hash")


def test_validation():
    assert validate_registration("leslie", "securepass")[0] is True
    assert validate_registration("ab", "pass")[0] is False         # too short username
    assert validate_registration("valid", "short")[0] is False     # too short password
    assert validate_registration("bad name!", "password123")[0] is False  # special chars
    print("PASS: test_validation")


def test_brute_force_lockout():
    ip = "192.168.1.99"
    for _ in range(5):
        record_failed_attempt(ip)
    assert is_locked_out(ip) is True
    reset_attempts(ip)
    assert is_locked_out(ip) is False
    print("PASS: test_brute_force_lockout")


if __name__ == "__main__":
    test_password_hash()
    test_validation()
    test_brute_force_lockout()
    print("\nAll security tests passed.")
