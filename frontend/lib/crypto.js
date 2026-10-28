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

export async function createEphemeralSigningKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"],
  );
  const publicBytes = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { privateKey: pair.privateKey, publicKey: toBase64(publicBytes) };
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

function textEnvelope(sessionId, sequence, nonce, ciphertext) {
  return textEncoder.encode(`CipherLink text signature v1\n${sessionId}\n${sequence}\n${nonce}\n${ciphertext}`);
}

export async function signTextEnvelope(privateKey, sessionId, sequence, nonce, ciphertext) {
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    textEnvelope(sessionId, sequence, nonce, ciphertext),
  );
  return toBase64(new Uint8Array(signature));
}

export async function verifyTextEnvelope(publicKeyBase64, sessionId, sequence, nonce, ciphertext, signatureBase64) {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    fromBase64(publicKeyBase64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    fromBase64(signatureBase64),
    textEnvelope(sessionId, sequence, nonce, ciphertext),
  );
}

export async function measureTextAnalysis(text, ciphertextBase64) {
  const bytes = textEncoder.encode(text);
  const ciphertextBytes = fromBase64(ciphertextBase64);
  const hashStart = performance.now();
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hashTimeMs = performance.now() - hashStart;
  const digestHex = Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();

  // These measurements are isolated experiments with disposable AES-CBC keys.
  // The fixed IV is reused only for the paired diagnostic samples and never for chat data.
  const probe = new Uint8Array(16);
  probe.set(bytes.subarray(0, 16));
  const flippedProbe = probe.slice();
  flippedProbe[0] ^= 1;
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const [keyA, keyB] = await Promise.all([
    crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, false, ["encrypt"]),
    crypto.subtle.generateKey({ name: "AES-CBC", length: 256 }, false, ["encrypt"]),
  ]);
  const [base, changedInput, changedKey] = await Promise.all([
    crypto.subtle.encrypt({ name: "AES-CBC", iv }, keyA, probe),
    crypto.subtle.encrypt({ name: "AES-CBC", iv }, keyA, flippedProbe),
    crypto.subtle.encrypt({ name: "AES-CBC", iv }, keyB, probe),
  ]);

  function compareBlocks(leftBuffer, rightBuffer) {
    const left = new Uint8Array(leftBuffer).subarray(0, 16);
    const right = new Uint8Array(rightBuffer).subarray(0, 16);
    let changedBits = 0;
    let changedBytes = 0;
    for (let index = 0; index < 16; index += 1) {
      const difference = left[index] ^ right[index];
      if (difference) changedBytes += 1;
      for (let bit = difference; bit; bit &= bit - 1) changedBits += 1;
    }
    return { changedBitsPercent: (changedBits / 128) * 100, changedBytesPercent: (changedBytes / 16) * 100 };
  }

  const frequencies = new Uint32Array(256);
  for (const byte of ciphertextBytes) frequencies[byte] += 1;
  const ciphertextEntropy = ciphertextBytes.length
    ? frequencies.reduce((entropy, count) => {
      if (!count) return entropy;
      const probability = count / ciphertextBytes.length;
      return entropy - probability * Math.log2(probability);
    }, 0)
    : 0;

  return {
    digestHex,
    hashTimeMs,
    ciphertextEntropy,
    confusion: compareBlocks(base, changedKey),
    avalanche: compareBlocks(base, changedInput),
  };
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

