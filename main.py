from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from dataguard import Safezone, SettingJWT, AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.responses import JSONResponse
from jwt_bearer import JWTBearer
import base64
import binascii

def is_base64(data: str) -> bool:
    try:
        base64.b64decode(data, validate=True)
        return True
    except Exception:
        return False

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

@app.post('/encrypt', dependencies=[Depends(JWTBearer())])
def encrypt(data: str):
    safezone = Safezone()
    encrypted_data = safezone.encrypt_with_aes_cbc(data)
    return {"encrypted_data": encrypted_data}

@app.post('/decrypt', dependencies=[Depends(JWTBearer())])
def decrypt(encrypted_data: str):
    if not is_base64(encrypted_data):
        raise HTTPException(status_code=400, detail="Input is not valid Base64")

    safezone = Safezone()
    try:
        decrypted_data = safezone.decrypt_with_aes_cbc(encrypted_data)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Invalid Base64 encoding")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

    return {"decrypted_data": decrypted_data}

@app.get('/generate-client-credentials', dependencies=[Depends(JWTBearer())])
def generate_client_credentials():
    safezone = Safezone()
    client_id, secret_key = safezone.generate_client_credentials()
    return {"client_id": client_id, "secret_key": secret_key}

@app.get('/generate-encryption-key', dependencies=[Depends(JWTBearer())])
def generate_encryption_key():
    safezone = Safezone()
    key = safezone.generate_encryption_key()
    return {"key": base64.b64encode(key).decode('utf-8')}

@app.get('/generate-iv', dependencies=[Depends(JWTBearer())])
def generate_iv():
    safezone = Safezone()
    iv = safezone.generate_iv()
    return {"iv": base64.b64encode(iv).decode('utf-8')}

@app.post('/create-access-token')
async def create_access_token(user: User, Authorize: AuthJWT = Depends()):
    safezone = Safezone()
    access_token, refresh_token = safezone.create_access_token(Authorize, user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

@app.post('/refresh-token')
def refresh_token(Authorize: AuthJWT = Depends()):
    Authorize.jwt_refresh_token_required()
    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}