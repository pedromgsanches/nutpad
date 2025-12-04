from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import os

class User(UserMixin):
    def __init__(self, id, username, role='user', is_active=True):
        self.id = id
        self.username = username
        self.role = role
        self._is_active = is_active
    
    @property
    def is_active(self):
        return self._is_active
    
    @staticmethod
    def hash_password(password):
        return generate_password_hash(password)
    
    @staticmethod
    def verify_password(stored_password, provided_password):
        salt = bytes.fromhex(stored_password[:64])
        stored_key = bytes.fromhex(stored_password[64:])
        key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000
        )
        return key == stored_key
    
    @staticmethod
    def get(user_id):
        from app.database import get_db
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT id, username, role, is_active FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1], user[2], user[3])
        return None
    
    @staticmethod
    def authenticate(username, password):
        from app.database import get_db
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user_data = cursor.fetchone()
        if user_data and check_password_hash(user_data['password'], password):
            # Verificar se o usuário está ativo
            user = User(user_data['id'], user_data['username'], user_data['role'], user_data['is_active'])
            return user
        return None
    
    @staticmethod
    def change_password(user_id, current_password, new_password):
        from app.database import get_db
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], current_password):
            cursor.execute('UPDATE users SET password = ? WHERE id = ?',
                         (generate_password_hash(new_password), user_id))
            db.commit()
            return True
        return False