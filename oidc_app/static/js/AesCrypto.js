// AesCrypto.js
// AES-GCM + AES key wrapping with RSA-OAEP-256 (WebCrypto).
// Exposes encryptAndWrap({ payloadObj, aadObj, serverPubJwk, serverKid }).

// ======================= Config =======================
const JWKS_URL = "/.well-known/jwks.json"; 

// ======================= Utils ========================
const te = new TextEncoder();
const td = new TextDecoder();

function toBase64url(u8) {
  let b64 = btoa(String.fromCharCode(...u8));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(b64u) {
  const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64u.length + 3) % 4);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8;
}

// =================== AES-GCM (Core) ===================
export async function generateAesGcmKey() {

  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,                      // <- important
    ["encrypt", "decrypt"]
  );
}

export async function encryptBytes(plaintextU8, aesKey, ivU8, aadU8) {
  const iv = ivU8 || crypto.getRandomValues(new Uint8Array(12));
  const params = aadU8
    ? { name: "AES-GCM", iv, additionalData: aadU8 }
    : { name: "AES-GCM", iv };

  const ctBuf = await crypto.subtle.encrypt(params, aesKey, plaintextU8);
  return {
    iv, // Uint8Array(12)
    ciphertext: new Uint8Array(ctBuf) // there is a tag included (WebCrypto)
  };
}

export async function decryptBytes(ciphertextU8, aesKey, ivU8, aadU8) {
  const params = aadU8
    ? { name: "AES-GCM", iv: ivU8, additionalData: aadU8 }
    : { name: "AES-GCM", iv: ivU8 };

  const ptBuf = await crypto.subtle.decrypt(params, aesKey, ciphertextU8);
  return new Uint8Array(ptBuf);
}

// Helpers
export async function encryptString(plaintext, aesKey, aadStr) {
  const aadU8 = typeof aadStr === "string" ? te.encode(aadStr) : undefined;
  const { iv, ciphertext } = await encryptBytes(te.encode(plaintext), aesKey, undefined, aadU8);
  return {
    iv_b64u: toBase64url(iv),
    ct_b64u: toBase64url(ciphertext)
  };
}

export async function decryptToString(ct_b64u, iv_b64u, aesKey, aadStr) {
  const aadU8 = typeof aadStr === "string" ? te.encode(aadStr) : undefined;
  const pt = await decryptBytes(fromBase64url(ct_b64u), aesKey, fromBase64url(iv_b64u), aadU8);
  return td.decode(pt);
}

// =========== JWKS fetch + RSA-OAEP import =============
async function fetchRemoteJwks(jwksUrl = JWKS_URL) {
  const res = await fetch(jwksUrl, { method: "GET", cache: "no-store" });
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  return res.json();
}

function pickRsaOaep256Jwk(jwks, wantKid) {
  if (!jwks || !Array.isArray(jwks.keys)) throw new Error("Invalid JWKS format");
  if (wantKid) {
    const byKid = jwks.keys.find(k => k.kid === wantKid);
    if (byKid) return byKid;
  }
  let jwk = jwks.keys.find(k => k.alg === "RSA-OAEP-256");
  if (!jwk) jwk = jwks.keys.find(k => k.kty === "RSA");
  if (!jwk) throw new Error("No RSA key found in JWKS");
  return jwk;
}

async function importRsaPublicKeyFromJwk(jwk) {
// Include "wrapKey" in usages
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt", "wrapKey"]
  );
}

// ====== Wrap AES key (RSA-OAEP-256 via JWK/JWKS) ======
async function wrapAesKeyWithPublicKey(aesKey, pubKey) {
  // Key wrapping requires an extractable AES key; surface clear errors instead of exporting
  try {
    const wrappedBuf = await crypto.subtle.wrapKey("raw", aesKey, pubKey, { name: "RSA-OAEP" });
    return new Uint8Array(wrappedBuf);
  } catch (e) {
    throw new Error(`Failed to wrap AES key (likely not extractable): ${e?.message || e}`);
  }
}

export async function wrapAesKeyWithRemotePublicKey(aesKey, { jwksUrl = JWKS_URL, serverKid } = {}) {
  const jwks = await fetchRemoteJwks(jwksUrl);
  const jwk = pickRsaOaep256Jwk(jwks, serverKid);
  const kid = jwk.kid || null;
  const pubKey = await importRsaPublicKeyFromJwk(jwk);
  const wrappedU8 = await wrapAesKeyWithPublicKey(aesKey, pubKey);
  return { wrapped_b64u: toBase64url(wrappedU8), kid, alg: "RSA-OAEP-256", kty: "RSA" };
}

export async function wrapAesKeyWithProvidedJwk(aesKey, serverPubJwk) {
  const pubKey = await importRsaPublicKeyFromJwk(serverPubJwk);
  const kid = serverPubJwk.kid || null;
  const wrappedU8 = await wrapAesKeyWithPublicKey(aesKey, pubKey);
  return { wrapped_b64u: toBase64url(wrappedU8), kid, alg: "RSA-OAEP-256", kty: "RSA" };
}

// ========= API for the FormHandler =================
// Sign: encryptAndWrap({ payloadObj, aadObj, serverPubJwk, serverKid })
export async function encryptAndWrap({ payloadObj, aadObj, serverPubJwk, serverKid } = {}) {
  if (payloadObj === undefined) throw new Error("encryptAndWrap: payloadObj requerido");

  // 1) Generate AES-GCM 256 (extractable:true for wrap)
  const aesKey = await generateAesGcmKey();

  // 2) Get the plaintext ready (payload JSON)
  const plaintextU8 = te.encode(JSON.stringify(payloadObj));

  // 3) Get AAD
  let aadU8;
  if (aadObj !== undefined && aadObj !== null) {
    aadU8 = te.encode(JSON.stringify(aadObj));
  }

  // 4) Encrypt with AES-GCM
  const { iv, ciphertext } = await encryptBytes(plaintextU8, aesKey, undefined, aadU8);

  // 5) Envelope the AES key with RSA-OAEP-256
  let wrapRes;
  if (serverPubJwk && typeof serverPubJwk === "object") {
    wrapRes = await wrapAesKeyWithProvidedJwk(aesKey, serverPubJwk);
  } else {
    wrapRes = await wrapAesKeyWithRemotePublicKey(aesKey, { jwksUrl: JWKS_URL, serverKid });
  }

  // 6) Response for the backend
  return {
    // AES-GCM payload
    iv_b64u: toBase64url(iv),                     // IV (12 bytes)
    ct_b64u: toBase64url(ciphertext),             // ciphertext + tag (WebCrypto concatenates)
    enc: "A256GCM",

    // Enveloped Key
    wrapped_aes_b64u: wrapRes.wrapped_b64u,
    kid: wrapRes.kid || serverKid || null,
    alg: wrapRes.alg,
    kty: wrapRes.kty,
    aad_b64u: toBase64url(aadU8)
  };
}

// ============= Optional export/import AES =============
export async function exportAesRaw(aesKey) {
  return new Uint8Array(await crypto.subtle.exportKey("raw", aesKey));
}
export async function importAesRaw(raw32bytes) {
  return crypto.subtle.importKey(
    "raw",
    raw32bytes,
    { name: "AES-GCM" },
    true,
    ["encrypt", "decrypt"]
  );
}
