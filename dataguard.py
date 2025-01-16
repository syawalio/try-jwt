import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
from pydantic import BaseModel
from fastapi_jwt_auth import AuthJWT
from datetime import timedelta
from config import Config


class SettingJWT(BaseModel):
    authjwt_secret_key: str = Config.SECRET_KEY
    authjwt_algorithm: str = "RS256"
    authjwt_public_key: str = Config.PUBLIC_KEY
    authjwt_private_key: str = Config.PRIVATE_KEY
    authjwt_access_token_expires: int = timedelta(minutes=15)
    authjwt_refresh_token_expires: int = timedelta(days=30)
    authjwt_token_location: set = {"headers"}
    authjwt_cookie_csrf_protect: bool = True
    authjwt_cookie_samesite: str = "lax"

@AuthJWT.load_config
def get_config():
    return SettingJWT()

class Safezone:
    def __init__(self):
        self.client_id = Config.CLIENT_ID
        self.key = base64.b64decode(Config.ENCRYPTION_KEY)
        self.iv = base64.b64decode(Config.IV)

        if len(self.key) not in [16, 24, 32]:
            raise ValueError("Invalid AES key length. Must be 16, 24, or 32 bytes.")
        if len(self.iv) != 16:
            raise ValueError("Invalid AES IV length. Must be 16 bytes.")

    def generate_client_credentials(self):
        client_id = secrets.token_hex(16)
        secret_key = secrets.token_hex(32)
        return client_id, secret_key

    def generate_encryption_key(self):
        return os.urandom(32)

    def generate_iv(self):
        return os.urandom(16)

    def encrypt_with_aes_cbc(self, data: str) -> str:
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(encrypted_data).decode()

    def decrypt_with_aes_cbc(self, encrypted_data: str) -> str:
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            padded_data = decryptor.update(base64.b64decode(encrypted_data)) + decryptor.finalize()
        except Exception:
            raise ValueError("Decryption failed. Invalid encrypted data.")

        unpadder = padding.PKCS7(128).unpadder()
        try:
            data = unpadder.update(padded_data) + unpadder.finalize()
        except Exception:
            raise ValueError("Decryption failed due to invalid padding.")

        return data.decode()

    def create_access_token(self, Authorize, client_id: str) -> str:
        encrypted_client_id = self.encrypt_with_aes_cbc(client_id)
        access_token = Authorize.create_access_token(subject=encrypted_client_id, expires_time=timedelta(minutes=15))
        refresh_token = Authorize.create_refresh_token(subject=encrypted_client_id)
        return access_token, refresh_token
