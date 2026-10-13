import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export const MAX_MESSAGE_BYTES = 64 * 1024;
export const ALGORITHM = 'ML-KEM-768/HKDF-SHA-256/AES-256-GCM';
const MAX_ENVELOPE_CHARS = 200_000;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const info = encoder.encode('pqc-vault-enterprise:sealed-message:v1');
const aad = encoder.encode('pqc-vault-enterprise:v1:' + ALGORITHM);

function requireWebCrypto() {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) {
    throw new Error('Secure-context Web Crypto is required.');
  }
}

function checkedMessage(message) {
  if (typeof message !== 'string' || message.length > MAX_MESSAGE_BYTES) {
    throw new Error('Message must be text no longer than 64 KiB.');
  }
  const bytes = encoder.encode(message);
  if (bytes.length > MAX_MESSAGE_BYTES) {
    throw new Error('UTF-8 message exceeds 64 KiB.');
  }
  return bytes;
}

export function toBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value, expectedLength) {
  if (typeof value !== 'string' || value.length > MAX_ENVELOPE_CHARS ||
      !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('Invalid base64url value.');
  }
  let bytes;
  try {
    const decoded = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
    bytes = Uint8Array.from(decoded, ch => ch.charCodeAt(0));
  } catch {
    throw new Error('Invalid base64url value.');
  }
  if ((expectedLength !== undefined && bytes.length !== expectedLength) ||
      toBase64Url(bytes) !== value) {
    throw new Error('Invalid base64url length or encoding.');
  }
  return bytes;
}

async function deriveAesKey(sharedSecret, salt) {
  const material = await crypto.subtle.importKey(
    'raw', sharedSecret, 'HKDF', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function createVaultSession() {
  requireWebCrypto();
  const kem = ml_kem768.keygen();
  const dsa = ml_dsa65.keygen();
  let destroyed = false;

  function ensureActive() {
    if (destroyed) throw new Error('Session has been cleared.');
  }

  return {
    publicKeys() {
      ensureActive();
      return {
        kem: toBase64Url(kem.publicKey),
        dsa: toBase64Url(dsa.publicKey),
      };
    },

    async seal(message) {
      ensureActive();
      const plaintext = checkedMessage(message);
      const { cipherText, sharedSecret } = ml_kem768.encapsulate(kem.publicKey);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      try {
        const key = await deriveAesKey(sharedSecret, salt);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
          key, plaintext
        ));
        return JSON.stringify({
          version: 1,
          algorithm: ALGORITHM,
          kemCiphertext: toBase64Url(cipherText),
          salt: toBase64Url(salt),
          iv: toBase64Url(iv),
          ciphertext: toBase64Url(ciphertext),
        }, null, 2);
      } finally {
        sharedSecret.fill(0);
      }
    },

    async open(json) {
      ensureActive();
      if (typeof json !== 'string' || json.length > MAX_ENVELOPE_CHARS) {
        throw new Error('Sealed envelope is too large.');
      }
      let envelope;
      try {
        envelope = JSON.parse(json);
      } catch {
        throw new Error('Sealed envelope is not valid JSON.');
      }
      if (!envelope || typeof envelope !== 'object' ||
          Array.isArray(envelope) || envelope.version !== 1 ||
          envelope.algorithm !== ALGORITHM) {
        throw new Error('Unsupported sealed envelope.');
      }
      const cipherText = fromBase64Url(envelope.kemCiphertext, 1088);
      const salt = fromBase64Url(envelope.salt, 16);
      const iv = fromBase64Url(envelope.iv, 12);
      const ciphertext = fromBase64Url(envelope.ciphertext);
      if (ciphertext.length < 16 || ciphertext.length > MAX_MESSAGE_BYTES + 16) {
        throw new Error('Ciphertext size is invalid.');
      }
      const secret = ml_kem768.decapsulate(cipherText, kem.secretKey);
      try {
        const key = await deriveAesKey(secret, salt);
        const plaintext = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
          key, ciphertext
        );
        return decoder.decode(plaintext);
      } catch {
        throw new Error('Authentication failed: wrong session or altered envelope.');
      } finally {
        secret.fill(0);
      }
    },

    sign(message) {
      ensureActive();
      return toBase64Url(ml_dsa65.sign(checkedMessage(message), dsa.secretKey));
    },

    verify(message, signature) {
      ensureActive();
      const bytes = checkedMessage(message);
      const sig = fromBase64Url(signature, 3309);
      return ml_dsa65.verify(sig, bytes, dsa.publicKey);
    },

    destroy() {
      if (!destroyed) {
        kem.secretKey.fill(0);
        dsa.secretKey.fill(0);
        destroyed = true;
      }
    },
  };
}

export async function publicKeyFingerprint(value) {
  requireWebCrypto();
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', fromBase64Url(value)));
  return Array.from(digest.subarray(0, 12), byte => byte.toString(16).padStart(2, '0')).join(':');
}
