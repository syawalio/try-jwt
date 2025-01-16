import os


class Config:
    SECRET_KEY = "671c11cffad21bd782215615c1b7f44605728c9c11ccdc0e17a29f09f2e31f5a"
    CLIENT_ID = "c9b65384dd4a2a2e0575e2ede5350d77"
    ENCRYPTION_KEY = "ktchKpGvd7SkBXIh9KejqZQGylfCk8ggY1OyDS5miH4="
    IV = "AJDg5x0zFjsCjND89eIixA=="
    
    with open("c:/BJB Coding/Python Classical/try-jwt/oauth-public.key", "r") as public_key_file:
        PUBLIC_KEY = public_key_file.read()
    
    with open("c:/BJB Coding/Python Classical/try-jwt/oauth-private.key", "r") as private_key_file:
        PRIVATE_KEY = private_key_file.read()