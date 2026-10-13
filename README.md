# PQC Vault — browser reference

A browser-based demonstration of post-quantum key encapsulation, authenticated encryption, and digital signatures. This repository began as an empty scaffold; it is **not** an enterprise key-management service.

## What it does

- Generates ephemeral **ML-KEM-768** and **ML-DSA-65** key pairs locally.
- Seals UTF-8 text using ML-KEM-768, HKDF-SHA-256, and AES-256-GCM.
- Opens and authenticates a JSON envelope with the **same browser session's** private key.
- Signs and verifies text with ML-DSA-65; edits invalidate signatures.
- Displays short SHA-256 fingerprints and allows copying public keys.
- Clears inputs and overwrites private-key byte arrays on a best-effort basis when the session is cleared.

## Usage

Open the deployed site once its GitHub Pages deployment is verified, or run it locally. Click **Generate key pairs**, enter test text, then use **Seal message** and **Open envelope**. In the signature panel, enter text, select **Sign message**, and select **Verify signature**. Change the text to observe rejection.

**Important:** Reloading, navigating away, or clearing the session makes encrypted messages from that session unrecoverable. No key export, import, persistent storage, or cross-session recovery is provided.

## Security and privacy boundaries

- All message processing and key generation run in the local browser; the application itself has no server API, telemetry, cookies, or browser storage.
- Only public keys, signatures, and ciphertext can be copied from the UI. Private keys stay in session memory but cannot be guaranteed to be zeroized by a managed JavaScript runtime.
- No identity binding, authenticated public-key distribution, authorization, hardware security module, audit log, backup, recovery, multi-user support, or protection against a compromised browser/device.
- The underlying [noble-post-quantum](https://github.com/paulmillr/noble-post-quantum) JavaScript library **does not claim constant-time execution or an independent security audit**. Browser execution cannot provide a side-channel-resistant custody boundary.
- The plaintext limit is 64 KiB. Do not submit sensitive, regulated, confidential, or production information.
- A production deployment should use threat modeling, authenticated key management, hardened cryptographic providers, tests against published vectors, and independent security review.

Algorithms follow ML-KEM and ML-DSA in [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). The envelope is an **application-specific demonstration format**, not an interoperable standard.

## Local development

Node.js 22 or newer is required. In a terminal, run these commands:

    npm install
    npm run dev
    npm run lint
    npm test
    npm run build
    npm run preview

The build emits static files in the dist directory. GitHub Actions runs syntax checks, regression tests, a production dependency audit, and the build on pull requests. Pushes to main also attempt GitHub Pages deployment.

## Browser compatibility

A modern browser with JavaScript, secure-context Web Crypto, and ES modules. The Clipboard API is needed only to copy public keys. Run on HTTPS or localhost. No browser-based Python interpreter is needed.

## Technology

Vanilla JavaScript, Vite, [@noble/post-quantum](https://www.npmjs.com/package/@noble/post-quantum), HKDF and AES-GCM from Web Crypto. No framework or backend.

## License

MIT. See [LICENSE](LICENSE).
