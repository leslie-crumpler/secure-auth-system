"""models.py - User model for Secure Auth System"""
from database import get_connection

class UserModel:
    @staticmethod
    def create(username, password_hash):
        conn = get_connection()
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        conn.close()

    @staticmethod
    def find_by_username(username):
        conn = get_connection()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        return user
