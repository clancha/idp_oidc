import time, os, base64, hashlib
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

import json
import jwt
from jwt.algorithms import RSAAlgorithm
from flask import current_app

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def randstr(n: int = 32) -> str:
    return b64url(os.urandom(n))

# Clave RSA efímera para firmar id_token (solo demo)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# Generamos clave RSA efímera (solo para demo, en real usarías una fija)
_RSA_PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_JWK_PUB = json.loads(RSAAlgorithm.to_jwk(_RSA_PRIVATE.public_key()))
_KID = "demo-kid-1"


@dataclass
class Client:
    client_id: str
    redirect_uris: list[str]

@dataclass
class User:
    sub: str
    email: str
    name: str

@dataclass
class AuthCode:
    code: str
    client_id: str
    redirect_uri: str
    sub: str
    scope: str
    nonce: Optional[str]
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    exp: int = field(default_factory=lambda: int(time.time()) + 300)  # 5 min

@dataclass
class AccessToken:
    token: str
    sub: str
    scope: str
    exp: int = field(default_factory=lambda: int(time.time()) + 3600)

# “BD” en memoria
CLIENTS: Dict[str, Client] = {}
CODES: Dict[str, AuthCode] = {}
TOKENS: Dict[str, AccessToken] = {}
SESSIONS: Dict[str, User] = {}  # muy simple: session_id -> User

def init_demo_data():
    cfg = current_app.config
    CLIENTS[cfg["CLIENT_ID"]] = Client(
        client_id=cfg["CLIENT_ID"],
        redirect_uris=[cfg["REDIRECT_URI"]],
    )

def get_client(client_id: str) -> Optional[Client]:
    return CLIENTS.get(client_id)

def issue_code(client_id: str, redirect_uri: str, user: User, scope: str,
               nonce: Optional[str], code_challenge: Optional[str], method: Optional[str]) -> AuthCode:
    code = randstr(32)
    item = AuthCode(code=code, client_id=client_id, redirect_uri=redirect_uri,
                    sub=user.sub, scope=scope, nonce=nonce,
                    code_challenge=code_challenge, code_challenge_method=method)
    CODES[code] = item
    return item

def exchange_code(code: str, redirect_uri: str, client_id: str,
                  code_verifier: Optional[str]) -> Tuple[User, dict]:
    item = CODES.pop(code, None)
    print(item)
    if not item or item.exp < time.time():
        raise ValueError("authorization_code inválido o expirado")
    if item.redirect_uri != redirect_uri or item.client_id != client_id:
        raise ValueError("redirect_uri o client_id no coinciden")

    # PKCE
    if item.code_challenge and False:  # Quitar la condición imposible cuando se implemtnte PKCE
        if not code_verifier:
            raise ValueError("falta code_verifier")
        if item.code_challenge_method == "S256":
            digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
            challenge = b64url(digest)
        else:
            challenge = code_verifier
        if challenge != item.code_challenge:
            raise ValueError("PKCE inválido")

    user = User(sub=item.sub, email=f"{item.sub}@example.com", name=item.sub.title())
    print(user)
    # access_token
    at = AccessToken(token=randstr(32), sub=user.sub, scope=item.scope)
    TOKENS[at.token] = at

    # id_token
    now = int(time.time())
    claims = {
        "iss": current_app.config["OIDC_ISSUER"],
        "aud": client_id,
        "sub": user.sub,
        "exp": now + 3600,
        "iat": now,
        "email": user.email,
        "name": user.name,
    }
    if item.nonce:
        claims["nonce"] = item.nonce

    id_token = jwt.encode(
        claims,
        _RSA_PRIVATE,
        algorithm="RS256",
        headers={"kid": _KID}
    )

    return user, {
        "access_token": at.token,
        "token_type": "Bearer",
        "expires_in": at.exp - now,
        "id_token": id_token,
        "scope": item.scope,
    }

def userinfo_from_bearer(bearer: str) -> dict:
    at = TOKENS.get(bearer)
    if not at or at.exp < time.time():
        raise ValueError("token inválido")
    # En demo reconstruimos claims sencillos
    return {
        "sub": at.sub,
        "email": f"{at.sub}@example.com",
        "name": at.sub.title(),
    }

def jwks() -> dict:
    jwk = _JWK_PUB.copy()
    jwk["kid"] = _KID
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return {"keys": [jwk]}


from dataclasses import dataclass

@dataclass
class CredentialRecord:
    username: str
    rp_id: str
    user_id: str
    credential_id_b64: str
    public_key_b64: str
    alg: str = "ES256"
    sign_count: int = 0

# Mapa username:rp_id -> credencial
CREDENTIALS: dict[str, CredentialRecord] = {}

def cred_key(username: str, rp_id: str) -> str:
    return f"{username}:{rp_id}"

def save_credential(rec: CredentialRecord) -> None:
    CREDENTIALS[cred_key(rec.username, rec.rp_id)] = rec

def get_credential(username: str, rp_id: str) -> CredentialRecord | None:
    return CREDENTIALS.get(cred_key(username, rp_id))