# TODO. Traducir todos los mensajes de error al ingles

from urllib.parse import urlencode, urlparse
import os, json, base64, hashlib, requests, base64, hashlib

from flask import Blueprint, request, jsonify, current_app, redirect, render_template, session, abort, flash, make_response

from .model import (
    init_demo_data, get_client, issue_code, exchange_code,
    userinfo_from_bearer, jwks, User,
    save_credential, get_credential, CredentialRecord
)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.exceptions import InvalidSignature

bp = Blueprint("oidc", __name__)


# ---------- Utils ----------
def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def random_challenge(n: int = 64) -> bytes:
    return os.urandom(n)


# ---------- Heatlh ----------
@bp.get("/health")
def health():
    return jsonify(status="ok", wscd_url=current_app.config["WSCD_URL"].rstrip("/"))


# ---------- Discovery / JWKS / UserInfo (igual) ----------
@bp.get("/.well-known/openid-configuration")
def discovery():
    iss = current_app.config["OIDC_ISSUER"].rstrip("/")
    iss_back = current_app.config["OIDC_ISSUER_BACKEND"].rstrip("/")
    return jsonify({
        "issuer": iss,
        "authorization_endpoint": f"{iss}/authorize",
        "token_endpoint": f"{iss_back}/token",
        "userinfo_endpoint": f"{iss}/userinfo",
        "jwks_uri": f"{iss_back}/jwks.json",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
    })

@bp.get("/jwks.json") # id_token keys
def jwks_json():
    return jwks()

with open("./sgx_test_keys/jwks.json") as f:
    JWKS = json.load(f)

@bp.route("/.well-known/jwks.json") # Devuelve la clave publica de RSA que tiene el SGX. HAY QUE QUITARLO CUANDO FUNCIONE Y PUBLICARLO EN EL SGX
def jwks_sgx():
    resp = make_response(jsonify(JWKS), 200)
    # CORS abierto para pruebas (restringe en prod)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp

@bp.get("/userinfo")
def userinfo():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return abort(401)
    token = auth.split(" ", 1)[1]
    try:
        return jsonify(userinfo_from_bearer(token))
    except Exception:
        return abort(401)

# ---------- Páginas Register/Login ----------
@bp.get("/register")
def register_page():
    return render_template("register.html",
        rp_id=current_app.config["RP_ID"]
    )

@bp.post("/register")
def do_register():
    """Llama al autenticador Cloud: POST /register y guarda la pública/credential."""
    username = (request.form.get("firstname") or "").strip()
    rp_id = (request.form.get("rpId") or current_app.config["RP_ID"]).strip()
    overwrite = "true" if request.form.get("overwrite") == "on" else "false"

    payload = request.form.get("enc_payload")

    if not username:
        flash("Falta el nombre.", "info")
        return redirect("/register")

    base = current_app.config["WSCD_URL"].rstrip("/")
    api_enroll = current_app.config["API_ENROLLMENT"].rstrip("/")

    nonce = random_challenge(32)
    try:
        resp = requests.post(f"{base}{api_enroll}", json={
            "username": username, "rpId": rp_id,
            "overwrite": overwrite, "enc_payload":payload, "nonce":base64.b64encode(nonce).decode('utf-8')
        }, timeout=5, verify=False)
        data = resp.json()
        if resp.status_code not in (200, 201):
            raise RuntimeError(data)
    except Exception as e:
        flash(f"Fallo registrando credencial: {e}", "info")
        return redirect("/register")

    # Persistir en el IdP
    rec = CredentialRecord(
        username=username,
        rp_id=rp_id,
        user_id=data["id"], # mismo id que se ha registrado en el authenticator
        credential_id_b64=data["id"],
        public_key_b64=data["pubKey"]
        # alg=data.get("alg", "ES256"),
        # sign_count=int(data.get("signCount", 0))
    )
    save_credential(rec)

    flash("Credencial registrada en el autenticador Cloud.", "success")
    return redirect("/success")

@bp.get("/success")
def success_register():
    return render_template("success.html")

@bp.get("/login")
def login_page():
    # Reusamos la plantilla de login con webcam que ya tienes
    return render_template("login.html", return_to=request.args.get("return_to", "/authorize"))

@bp.post("/login")
def do_login():
    """
    Recibe: firstname, password, face_b64 (del formulario).
    Construye las opciones WebAuthn, llama al /assertion del autenticador,
    y verifica la assertion usando la clave pública guardada en el IdP.
    """
    firstname = (request.form.get("firstname") or "").strip()
    return_to = request.form.get("return_to") or "/"

    rp_id = current_app.config["RP_ID"]
    origin = current_app.config["ORIGIN"]

    cred = get_credential(firstname, rp_id)
    allow = []
    if cred:
        allow = [{"id": cred.credential_id_b64, "type": "public-key"}]

    print(f"El cred es {cred}")
    challenge = random_challenge()
    # options = {
    #     "id":cred.user_id,
    #     "challenge": challenge,
    #     "rpId": rp_id,
    #     "origin": origin,
    #     "userVerification": "required",
    #     "allowCredentials": allow
    # }

    payload = request.form.get("enc_payload")

    base = current_app.config["WSCD_URL"].rstrip("/")
    api_verification = current_app.config["API_VERIFICATION"].rstrip("/")

    try:
        aresp = requests.post(f"{base}{api_verification}", json={
            "username": firstname,
            "rpId":rp_id,
            "overwrite":"true", ## CURRENTLY IT DONT MAKE SENSE
            "enc_payload":payload,
            "id": cred.user_id,
            "challenge": base64.b64encode(challenge).decode('utf-8')
            # "options": options
        }, timeout=8, verify=False)
        if not aresp.ok:
            raise RuntimeError(aresp.text)
        data = aresp.json()
    except Exception as e:
        flash(f"Error obteniendo assertion: {e}", "info")
        return redirect(f"/login?{urlencode({'return_to': return_to})}")

    # ----- Verificación de assertion -----
    try:
        if not cred:
            raise ValueError("No hay credencial registrada para este usuario en el IdP.")

        

        pub_key_bytes = base64.b64decode(cred.public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)

        print(f"El tipo de datos del signature es {type(data['signature'])}")
        print(f"La fima vale: {data['signature']}")

        signature_bytes = base64.b64decode(data["signature"])

        # Verificar la firma
        public_key.verify(signature_bytes, challenge)


    except InvalidSignature:
        flash("Firma inválida en assertion.", "info")
        return redirect(f"/login?{urlencode({'return_to': return_to})}")
    except Exception as e:
        flash(f"Assertion inválida: {e}", "info")
        return redirect(f"/login?{urlencode({'return_to': return_to})}")

    # ✅ Autenticación correcta: marcamos sesión y volvemos al authorize original
    session["user_sub"] = firstname
    return redirect(return_to)

# ---------- OAuth/OIDC core: /authorize y /token (sin cambios lógicos) ----------
@bp.get("/authorize")
def authorize():
    print(f"entrando....")
    q = request.args
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    print(f"Redirect URI: -> {redirect_uri}")
    response_type = q.get("response_type")
    scope = q.get("scope", "openid")
    state = q.get("state")
    nonce = q.get("nonce")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")

    if response_type != "code" or not client_id or not redirect_uri or not state:
        return abort(400, "parámetros requeridos")

    client = get_client(client_id)
    if not client or redirect_uri not in client.redirect_uris:
        return abort(400, "cliente o redirect_uri no válidos")

    sub = session.get("user_sub")
    if not sub:
        return_to = request.full_path
        return redirect(f"/login?{urlencode({'return_to': return_to})}")

    user = User(sub=sub, email=f"{sub}@example.com", name=sub.title())
    code = issue_code(client_id, redirect_uri, user, scope, nonce,
                      code_challenge, code_challenge_method)

    sep = "&" if urlparse(redirect_uri).query else "?"
    print("SALIENDO....")
    print(f"{redirect_uri}{sep}{urlencode({'code': code.code, 'state': state})}")
    return redirect(f"{redirect_uri}{sep}{urlencode({'code': code.code, 'state': state})}")

@bp.post("/token")
def token():
    print("Cambiando token.....")
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    code_verifier = request.form.get("code_verifier")

    if grant_type != "authorization_code":
        return abort(400, "grant_type inválido")

    try:
        user, token_set = exchange_code(code, redirect_uri, client_id, code_verifier)
        return jsonify(token_set)
    except Exception as e:
        return jsonify({"error": "invalid_grant", "error_description": str(e)}), 400



