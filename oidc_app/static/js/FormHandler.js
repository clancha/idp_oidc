import * as AesCrypto from "./AesCrypto.js";

export class FormHandler {
  constructor(imageFaceForm, {
    jwksUrl = "/.well-known/jwks.json",   // PONER AQUI LA URL DEL ENPOINT QUE EXPONGA LA PK RSA DEL WSCD
    formId  = "formulario",
    errorId = "form-error"
  } = {}) {
    this.imgForm  = imageFaceForm;
    this.form     = document.getElementById(formId);
    this.formError= document.getElementById(errorId);
    this.jwksUrl  = jwksUrl;

    if (!this.form) {
      console.error(`FormHandler: no se encontró el formulario con id="${formId}"`);
      return;
    }

    this.encInput = document.getElementById("enc_payload");
    if (!this.encInput) {
      this.encInput = document.createElement("input");
      this.encInput.type = "hidden";
      this.encInput.id   = "enc_payload";
      this.encInput.name = "enc_payload";
      this.form.appendChild(this.encInput);
    }

    this.onSubmit = this.onSubmit.bind(this);
    this.form.addEventListener("submit", this.onSubmit);
  }

  // ---------- Utils ----------
  showFormError(msg) {
    if (!this.formError) {
      console.error("[FormHandler]", msg);
      return;
    }
    this.formError.textContent = msg;
    this.formError.style.display = "block";
  }
  clearFormError() {
    if (!this.formError) return;
    this.formError.textContent = "";
    this.formError.style.display = "none";
  }

  b64urlFromBytes(bytes) {
    let str = "";
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    const b64 = btoa(str);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  randomNonceB64url(len = 12) {
    const u8 = new Uint8Array(len);
    crypto.getRandomValues(u8);
    return this.b64urlFromBytes(u8);
  }

  safeParseJson(txt) {
    try {
      return txt ? JSON.parse(txt) : null;
    } catch (e) {
      return null;
    }
  }

  async fetchServerEncKey() {
    try {
      const res = await fetch(this.jwksUrl, { cache: "no-store" });
      if (!res.ok) return null;
      const jwks = await res.json();
      if (!jwks?.keys?.length) return null;
      const k = jwks.keys.find(k => k.use === "enc") || jwks.keys[0];
      return k || null;
    } catch (e) {
      console.warn("JWKS fetch error:", e);
      return null;
    }
  }

  



  // ---------- Main submit ----------
  async onSubmit(e) {
    e.preventDefault();
    this.clearFormError();
    // 1) Basics
    const firstnameEl = document.getElementById("firstname");
    const passwordEl  = document.getElementById("password");
    const waEl        = document.getElementById("webauthn_options");

    const firstname = firstnameEl?.value?.trim() || "";
    const password  = passwordEl?.value?.trim() || "";
    const waText    = waEl?.value?.trim() || "";

    if (!firstname || !password) {
      this.showFormError("Completa nombre y contraseña.");
      return;
    }

    // 2) Ensure there is a photo
    try {
      await this.imgForm.prepareFaceIfNeeded();
    } catch (err) {
      this.showFormError(err?.message || "No se pudo preparar el rostro.");
      return;
    }

    const face_b64 = document.getElementById("face_raw_bgr8")?.value || "";
    if (!face_b64) {
      this.showFormError("Falta el rostro recortado.");
      return;
    }

    const passHash32 = await sha256Base64(password);             // 32 bytes

    // 3) Build a clear payload
    const payload = {
      firstname,
      password: passHash32, // secret when its ready                
      foto: face_b64,
      // meta: {
      //   ts: new Date().toISOString(),
      //   origin: location.origin,
      //   client: "idp-demo-v1"
      // }
    };
    console.log(payload);

    // 4) AAD (Aditional Authenticated Data) for fresh
    const aad = { ts: Date.now(), nonce: this.randomNonceB64url(12) };

    // 5) fetch the RSA_PK
    const serverPubJwk = await this.fetchServerEncKey();
    const serverKid    = serverPubJwk?.kid || null;

    try {
      // 6) Cipher and envolve
      const jwe = await AesCrypto.encryptAndWrap({
        payloadObj: payload,
        aadObj: aad,
        serverPubJwk: serverPubJwk || null,
        serverKid
      });

      // 7) Put enc_payload on the form
      const jweStr = JSON.stringify(jwe);
      this.encInput.value = toBase64Url(jweStr);

      // 8) Send
      this.form.submit();

    } catch (err) {
      console.error(err);
      this.showFormError("Error al cifrar datos: " + (err?.message || String(err))); // TODO. Traducir los mensajes 
    }
  }
}

function toBase64Url(str){
  let b64 = btoa(unescape(encodeURIComponent(str)));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
}

function toBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary); // Mantiene el padding '=' automáticamente
}

async function sha256Base64(str) {
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return toBase64(new Uint8Array(hashBuf));
}
