import './style.css';
import { createVaultSession, publicKeyFingerprint } from './crypto.js';

const byId = id => document.getElementById(id);
const sessionButtons = [...document.querySelectorAll('[data-requires-session]')];
let session = null;
let busy = false;

function setStatus(text, kind = 'neutral') {
  const status = byId('status');
  status.textContent = text;
  status.dataset.kind = kind;
}

function updateButtons() {
  for (const button of sessionButtons) button.disabled = !session || busy;
  byId('generate').disabled = busy;
  byId('clear').disabled = !session || busy;
  byId('session-chip').textContent = session ? 'Session active · local only' : 'No active session';
  byId('key-dot').classList.toggle('active', Boolean(session));
}

function clearFields() {
  for (const name of ['kem-public', 'dsa-public', 'message', 'envelope', 'opened', 'sign-message', 'signature']) {
    byId(name).value = '';
  }
  byId('kem-id').textContent = 'Not generated';
  byId('dsa-id').textContent = 'Not generated';
  byId('verification').textContent = 'No signature verified.';
  byId('verification').dataset.kind = 'neutral';
}

function discardSession() {
  if (session) session.destroy();
  session = null;
  clearFields();
  updateButtons();
}

async function perform(action) {
  if (busy) return;
  busy = true;
  updateButtons();
  try {
    await action();
  } catch (error) {
    setStatus(error instanceof Error ? error.message : 'Unexpected operation failure.', 'error');
  } finally {
    busy = false;
    updateButtons();
  }
}

byId('generate').addEventListener('click', () => perform(async () => {
  discardSession();
  session = createVaultSession();
  const publicKeys = session.publicKeys();
  byId('kem-public').value = publicKeys.kem;
  byId('dsa-public').value = publicKeys.dsa;
  byId('kem-id').textContent = await publicKeyFingerprint(publicKeys.kem);
  byId('dsa-id').textContent = await publicKeyFingerprint(publicKeys.dsa);
  setStatus('New independent ML-KEM-768 and ML-DSA-65 key pairs created in this browser session.', 'success');
}));

byId('clear').addEventListener('click', () => perform(() => {
  discardSession();
  setStatus('Session cleared. Stored private key arrays were overwritten on a best-effort basis.', 'neutral');
}));

byId('seal').addEventListener('click', () => perform(async () => {
  byId('envelope').value = await session.seal(byId('message').value);
  byId('opened').value = '';
  setStatus('Message sealed with ML-KEM-768, HKDF-SHA-256, and AES-256-GCM.', 'success');
}));

byId('open').addEventListener('click', () => perform(async () => {
  byId('opened').value = '';
  byId('opened').value = await session.open(byId('envelope').value);
  setStatus('Envelope authenticated and decrypted with the current session key.', 'success');
}));

byId('sign').addEventListener('click', () => perform(() => {
  byId('signature').value = session.sign(byId('sign-message').value);
  byId('verification').textContent = 'Signature created. Select Verify to check it.';
  byId('verification').dataset.kind = 'neutral';
  setStatus('Text signed with the session ML-DSA-65 secret key.', 'success');
}));

byId('verify').addEventListener('click', () => perform(() => {
  const valid = session.verify(byId('sign-message').value, byId('signature').value);
  byId('verification').textContent = valid ? 'Valid signature for this exact message and session public key.' : 'Invalid signature: content or signature does not match.';
  byId('verification').dataset.kind = valid ? 'success' : 'error';
  setStatus(valid ? 'ML-DSA-65 verification succeeded.' : 'ML-DSA-65 verification failed.', valid ? 'success' : 'error');
}));

for (const [id, field] of [['copy-kem', 'kem-public'], ['copy-dsa', 'dsa-public']]) {
  byId(id).addEventListener('click', () => perform(async () => {
    if (!navigator.clipboard?.writeText) throw new Error('Clipboard API is unavailable in this context.');
    await navigator.clipboard.writeText(byId(field).value);
    setStatus('Public key copied to clipboard.', 'success');
  }));
}

// Page navigation also invalidates secret material; JavaScript cannot guarantee zeroization.
window.addEventListener('pagehide', discardSession);
updateButtons();
