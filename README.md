# 🤝 Handshake: prove a *known* human is on the call

A response to YC's Fall 2026 Request for Startups, **"Proving You're Human"**. Deepfake voice and video calls, such as the $25M "CFO" video-call fraud, work because a face and a voice no longer prove who you're talking to. Handshake swaps that guesswork for cryptography: two people pair once, then either side can prove **"I hold the device key you paired with"** during a call, in a chat or before a transaction.

It's a static site: **no server, no accounts, no paid APIs, no tracking**. Everything uses WebCrypto and WebAuthn in the browser.

> ⚠️ **Handshake does not detect deepfakes.** It never analyses audio or video. It checks possession of a key you exchanged earlier. See the threat model below.

## How it works
1. **Device identity**: each browser creates an ECDSA P-256 key pair and stores it **non-extractable** in IndexedDB.
2. **Pairing (once)**: A creates a pairing code (a 256-bit shared secret plus A's public key) and hands it to B over a channel they already trust. B imports it and returns a reply code with B's public key.
3. **Live call check**
   - **Rotating code**: `HMAC-SHA256(secret, "hh-code|<owner key fp>|<30s window>")` → 6 digits (RFC 4226 truncation, ±1 window). Each code is tied to one direction, so echoing someone's own code back to them fails.
   - **Challenge-response**: the verifier reads out a random 5-character challenge, and the other side answers with `HMAC(secret, "hh-resp|<their fp>|<challenge>")`.
4. **Signed "verified human" token** (`HHT1.<payload>.<passkey assertion>.<ECDSA sig>`): a statement with expiry and nonce, signed by the device key. If a **passkey** is bound, signing also needs a WebAuthn assertion with `userVerification: "required"` over `SHA-256("HHT1."+payload)`. The verifier checks the challenge binding, the UP/UV flags and the ES256 signature. Verification succeeds only if the signing key belongs to a **paired contact**. A valid signature from an unknown key shows a warning, never a pass.

## Threat model (short version)
**Helps against:** impostors (including deepfakes) calling from new accounts or numbers without the paired device; forged, edited or expired approval messages; naive replay.
**Does not help against:** a compromised or unlocked device, malware, coercion or an insider; real-time relay through the real person (a social-engineering risk, so prefer challenges and say why you're asking); an intercepted pairing; lost browser storage (there's no backup or sync). The 6-digit codes give about 20 bits, which is fine for a live call but isn't a long-term credential. Without attestation, passkeys show that user verification happened, not what hardware was used.

## Run locally
```
python3 -m http.server 8000   # then open http://localhost:8000 (WebCrypto/WebAuthn need localhost or HTTPS)
```
Use two browsers or profiles to play both parties.

## Tests
`test/e2e.js` drives headless Chrome (puppeteer-core) with separate browser contexts for Alice, Bob and Mallory, plus a CDP virtual authenticator for the passkey:
```
npm i puppeteer-core && node test/e2e.js   # expects the site at http://localhost:8765
```

## Deploy
Push to GitHub and enable Pages (root). `.nojekyll` is included. Passkeys bind to the origin, so a passkey made on `localhost` won't work on the Pages domain.

---
Built by Satoshi Drops 🪂 [@SatoshiDropsHQ](https://x.com/SatoshiDropsHQ)
