import os
import base64

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-unsafe")
    OIDC_ISSUER = os.getenv("OIDC_ISSUER", "https://localhost:8080")
    OIDC_ISSUER_BACKEND = os.getenv("OIDC_ISSUER_BACKEND", "https://172.17.0.3:8080") # Docker internal address

    # Cliente de prueba (público)
    CLIENT_ID = os.getenv("CLIENT_ID", "rp")
    REDIRECT_URI = os.getenv("REDIRECT_URI", "https://localhost:5001/callback")

    # Cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    # WebAuthn Cloud    
    WSCD_URL = os.getenv("WSCD_URL", "") # Poner aqui la dirección del WSCD (esta vacía porque no hay dominio y usamos trycloudflare de momenot)
    RP_ID = os.getenv("RP_ID", "localhost")  # dominio base del IdP
    ORIGIN = os.getenv("ORIGIN", "https://localhost:8080")  # origin del IdP
    
    # Endpoints in the WSCD server
    API_ENROLLMENT = os.getenv("API_ENROLLMENT", "/api/mceliece/enrollment")
    API_VERIFICATION = os.getenv("API_VERIFICATION", "/api/mceliece/verification")