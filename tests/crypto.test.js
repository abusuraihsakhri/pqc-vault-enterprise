import test from 'node:test';
import assert from 'node:assert/strict';
import { createVaultSession, fromBase64Url, toBase64Url, publicKeyFingerprint, MAX_MESSAGE_BYTES } from '../src/crypto.js';

test('ML-KEM seal and authenticated AES-GCM open round trip', async () => {
  const vault = createVaultSession();
  try {
    const envelope = await vault.seal('Post-quantum test: Ω');
    const data = JSON.parse(envelope);
    assert.equal(data.version, 1);
    assert.equal(await vault.open(envelope), 'Post-quantum test: Ω');
    assert.equal(fromBase64Url(data.kemCiphertext).length, 1088);
    assert.equal(fromBase64Url(data.iv).length, 12);
  } finally {
    vault.destroy();
  }
});

test('opening with another session fails authentication', async () => {
  const first = createVaultSession();
  const second = createVaultSession();
  try {
    const envelope = await first.seal('secret');
    await assert.rejects(second.open(envelope), /Authentication failed/);
  } finally {
    first.destroy();
    second.destroy();
  }
});

test('modified ciphertext fails authenticated decryption', async () => {
  const vault = createVaultSession();
  try {
    const data = JSON.parse(await vault.seal('payload'));
    const ciphertext = fromBase64Url(data.ciphertext);
    ciphertext[0] ^= 1;
    data.ciphertext = toBase64Url(ciphertext);
    await assert.rejects(vault.open(JSON.stringify(data)), /Authentication failed/);
  } finally {
    vault.destroy();
  }
});

test('ML-DSA signatures validate and detect changed messages', () => {
  const vault = createVaultSession();
  try {
    const signature = vault.sign('attested value');
    assert.equal(vault.verify('attested value', signature), true);
    assert.equal(vault.verify('tampered value', signature), false);
  } finally {
    vault.destroy();
  }
});

test('session secrets are not exposed by the public key accessor', async () => {
  const vault = createVaultSession();
  const keys = vault.publicKeys();
  assert.equal(fromBase64Url(keys.kem).length, 1184);
  assert.equal(fromBase64Url(keys.dsa).length, 1952);
  assert.match(await publicKeyFingerprint(keys.kem), /^([a-f0-9]{2}:){11}[a-f0-9]{2}$/);
  assert.equal(Object.hasOwn(keys, 'secretKey'), false);
  vault.destroy();
  assert.throws(() => vault.sign('hello'), /cleared/);
  assert.throws(() => vault.publicKeys(), /cleared/);
});

test('malformed envelopes and excessive messages are rejected', async () => {
  const vault = createVaultSession();
  try {
    assert.throws(() => vault.sign('x'.repeat(MAX_MESSAGE_BYTES + 1)), /64 KiB/);
    assert.throws(() => fromBase64Url('not+base64'), /Invalid base64url/);
    await assert.rejects(vault.open('not json'), /valid JSON/);
    await assert.rejects(vault.open('{}'), /Unsupported/);
  } finally {
    vault.destroy();
  }
});
