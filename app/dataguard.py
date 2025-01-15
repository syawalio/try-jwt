import hashlib
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
import hmac
from pydantic import BaseModel
from fastapi_jwt_auth import AuthJWT
from datetime import datetime, timedelta
from typing import Dict
from config import Config

class SettingJWT(BaseModel):
    authjwt_secret_key: str = Config.SECRET_KEY
    authjwt_algorithm: str = "HS256"
    # authjwt_public_key: str = Config.JWT_SECRET_KEY
    # authjwt_private_key: str = Config.JWT_SECRET_KEY
    authjwt_access_token_expires: int = timedelta(minutes=15)
    authjwt_refresh_token_expires: int = timedelta(days=30)
    authjwt_token_location: set = {"headers"}
    authjwt_cookie_csrf_protect: bool = True
    authjwt_cookie_samesite: str = "lax"
    
class Safezone:
    def __init__(self):
        self.client_id = Config.CLIENT_ID
        self.key = Config.ENCRYPTION_KEY
        self.iv = Config.IV
        
    def generate_client_credentials(self):
        client_id = secrets.token_hex(16)
        secret_key = secrets.token_hex(32)
        return client_id, secret_key
    
    def generate_encryption_key(self):
        return os.urandom(32)
    
    def generate_iv(self):
        return os.urandom(16)
    
    def encrypt_with_aes_cbc(self, data: str) -> bytes:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return base64.b64encode(encrypted_data)
    
    def decrypt_with_aes_cbc(self, encrypted_data):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return data.decode()