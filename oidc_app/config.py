import os
import base64

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-unsafe")
    OIDC_ISSUER = os.getenv("OIDC_ISSUER", "https://idp.licorice-us.eu")
    OIDC_ISSUER_BACKEND = os.getenv("OIDC_ISSUER_BACKEND", "https://idp.licorice-us.eu") # Docker internal address

    # Cliente de prueba (público)
    CLIENT_ID = os.getenv("CLIENT_ID", "android-test-client")
    REDIRECT_URI = os.getenv("REDIRECT_URI", "myapp://callback")

    # Cookies
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False

    # WebAuthn Cloud    
    WSCD_URL = os.getenv("WSCD_URL", "https://wscd.carloslancha.es")
    RP_ID = os.getenv("RP_ID", "licorice-us.eu")  # domain of the RP
    ORIGIN = os.getenv("ORIGIN", "https://idp.licorice-us.eu")  # origin del IdP
    
    # Endpoints in the WSCD server
    API_ENROLLMENT = os.getenv("API_ENROLLMENT", "/api/mceliece/enrollment")
    API_VERIFICATION = os.getenv("API_VERIFICATION", "/api/mceliece/verification")