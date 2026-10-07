const textEncoder = new TextEncoder();

function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return window.btoa(binary);
}

function fromBase64(value) {
  const binary = window.atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function createEphemeralKeyPair() {
  if (!globalThis.crypto?.subtle) {
    throw new Error("This browser does not provide secure Web Crypto. Open CipherLink in a current browser over HTTPS.");
  }

  try {
    // Exportability is enabled only because this prototype's handshake inspector displays the private key.
    const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const privateBytes = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    return { privateKey: pair.privateKey, privateKeyBase64: toBase64(privateBytes), publicKey: toBase64(publicBytes) };
  } catch (error) {
    if (error?.name === "NotSupportedError") {
      throw new Error("X25519 is not supported by this browser. Please use an up-to-date Chrome, Edge, or Firefox browser.");
    }
    throw error;
  }
}

export async function deriveSessionMaterials(privateKey, peerPublicKey, sessionId) {
  const publicKey = await crypto.subtle.importKey("raw", fromBase64(peerPublicKey), { name: "X25519" }, false, []);
  const sharedSecretBytes = new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256));
  const inputKey = await crypto.subtle.importKey("raw", sharedSecretBytes, "HKDF", false, ["deriveKey"]);

  const sessionKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: textEncoder.encode(`CipherLink session ${sessionId}`),
      info: textEncoder.encode("CipherLink chat key v1"),
    },
    inputKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  return { sessionKey, sharedSecretBase64: toBase64(sharedSecretBytes) };
}

export async function createKeyFingerprint(localPublicKey, peerPublicKey, sessionId) {
  const participants = [localPublicKey, peerPublicKey].sort();
  const digest = new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(`CipherLink fingerprint v1|${sessionId}|${participants.join("|")}`),
  ));
  return Array.from(digest.slice(0, 8), (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase().match(/.{1,4}/g).join(" ");
}

export async function encryptText(key, sessionId, sequence, text) {
  return encryptBytes(key, `${sessionId}:${sequence}`, textEncoder.encode(text));
}

export async function decryptText(key, sessionId, sequence, nonce, ciphertext) {
  const plaintext = await decryptBytes(key, `${sessionId}:${sequence}`, nonce, ciphertext);
  return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

export async function encryptBytes(key, context, bytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: textEncoder.encode(context),
      tagLength: 128,
    },
    key,
    bytes,
  );
  return { nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(ciphertext)) };
}

export async function decryptBytes(key, context, nonce, ciphertext) {
  return new Uint8Array(await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: fromBase64(nonce),
      additionalData: textEncoder.encode(context),
      tagLength: 128,
    },
    key,
    fromBase64(ciphertext),
  ));
}

