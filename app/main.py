from fastapi import FastAPI, Depends
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
# from config import Config
from app.dataguard import Safezone, SettingJWT
import base64

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

@AuthJWT.load_config
def get_config():
    return SettingJWT()

@app.post('/login')
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        return {"msg": "Bad username or password"}
    
    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}

@app.get('/protected')
def protected(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()
    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}

@app.post('/encrypt')
def encrypt(data: str):
    safezone = Safezone()
    encrypted_data = safezone.encrypt_with_aes_cbc(data)
    return {"encrypted_data": encrypted_data}

@app.post('/decrypt')
def decrypt(encrypted_data: str):
    safezone = Safezone()
    decrypted_data = safezone.decrypt_with_aes_cbc(base64.b64decode(encrypted_data))
    return {"decrypted_data": decrypted_data}

@app.get('/generate-client-credentials')
def generate_client_credentials():
    safezone = Safezone()
    client_id, secret_key = safezone.generate_client_credentials()
    return {
        "client_id": client_id,
        "secret_key": secret_key
    }

@app.get('/generate-iv')
def generate_iv():
    safezone = Safezone()
    iv = safezone.generate_iv()
    return {
        "iv": base64.b64encode(iv).decode('utf-8')
    }