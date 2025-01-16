import time
import jwt
from config import Config

def decode_jwt(token: str) -> dict:
    try:
        decoded_token = jwt.decode(token, Config.PUBLIC_KEY, algorithms=["RS256"])
        return decoded_token if decoded_token["exp"] >= time.time() else None
    except:
        return {}