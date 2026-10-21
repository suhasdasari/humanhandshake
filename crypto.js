// Handshake crypto core: WebCrypto only, no dependencies.
const HH = (() => {
  const te = new TextEncoder(), td = new TextDecoder(), S = crypto.subtle;
  const b64u = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const ub64u = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((s.length+3)%4)), c => c.charCodeAt(0));
  const rand = n => crypto.getRandomValues(new Uint8Array(n));
  const sha = async d => new Uint8Array(await S.digest('SHA-256', typeof d === 'string' ? te.encode(d) : d));
  const fp = async raw => b64u((await sha(raw)).slice(0, 9)); // 12-char fingerprint of a public key
  async function hmac(secret, msg) {
    const k = await S.importKey('raw', secret, {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
    return new Uint8Array(await S.sign('HMAC', k, te.encode(msg)));
  }
  // RFC 4226 style dynamic truncation -> 6 digits
  const digits = h => { const o = h[h.length-1] & 15; const v = ((h[o]&127)<<24|h[o+1]<<16|h[o+2]<<8|h[o+3]) % 1e6; return String(v).padStart(6,'0'); };
  const STEP = 30;
  const win = (t = Date.now()) => Math.floor(t / 1000 / STEP);
  // Direction-bound rotating code: code of the holder of key `ownerFp`
  const code = async (secret, ownerFp, w = win()) => digits(await hmac(secret, `hh-code|${ownerFp}|${w}`));
  async function checkCode(secret, ownerFp, input, t = Date.now()) {
    for (const d of [0, -1, 1]) if (await code(secret, ownerFp, win(t) + d) === input) return true;
    return false;
  }
  const respond = async (secret, responderFp, chal) => digits(await hmac(secret, `hh-resp|${responderFp}|${chal.trim().toUpperCase()}`));
  const newChallenge = () => Array.from(rand(5), b => 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'[b & 31]).join('');
  // ECDSA identity
  const genIdentity = () => S.generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign', 'verify']);
  const rawPub = async k => new Uint8Array(await S.exportKey('raw', k));
  const ecSign = async (priv, data) => new Uint8Array(await S.sign({name:'ECDSA', hash:'SHA-256'}, priv, data));
  async function ecVerify(raw, sig, data) {
    const k = await S.importKey('raw', raw, {name:'ECDSA', namedCurve:'P-256'}, false, ['verify']);
    return S.verify({name:'ECDSA', hash:'SHA-256'}, k, sig, data);
  }
  // DER ECDSA signature (WebAuthn) -> raw r||s (WebCrypto)
  function derToRaw(der) {
    let i = 2; if (der[1] & 0x80) i += der[1] & 0x7f;
    const rd = () => { i++; const l = der[i++]; let v = der.slice(i, i + l); i += l; while (v.length > 32 && v[0] === 0) v = v.slice(1); const o = new Uint8Array(32); o.set(v, 32 - v.length); return o; };
    const r = rd(), s = rd(); const out = new Uint8Array(64); out.set(r); out.set(s, 32); return out;
  }
  async function verifyAssertion(a, expectedChallenge) {
    const cd = JSON.parse(td.decode(ub64u(a.cd)));
    if (cd.type !== 'webauthn.get' || cd.challenge !== b64u(expectedChallenge)) return {ok:false, why:'passkey challenge mismatch'};
    const ad = ub64u(a.ad); const flags = ad[32];
    if (!(flags & 1)) return {ok:false, why:'user not present'};
    const uv = !!(flags & 4);
    const signed = new Uint8Array([...ad, ...await sha(ub64u(a.cd))]);
    const k = await S.importKey('spki', ub64u(a.spki), {name:'ECDSA', namedCurve:'P-256'}, false, ['verify']);
    const ok = await S.verify({name:'ECDSA', hash:'SHA-256'}, k, derToRaw(ub64u(a.sig)), signed);
    return {ok, uv, origin: cd.origin, why: ok ? '' : 'bad passkey signature'};
  }
  // Token: HHT1.<payload>.<sig>  payload = {v,n,pub,iat,exp,msg,nonce,pk?}; sig = ECDSA over "HHT1."+payload+"."+(assertion||"")
  async function verifyToken(tok, contacts, now = Date.now()) {
    const parts = tok.trim().split('.');
    if (parts[0] !== 'HHT1' || parts.length !== 4) return {ok:false, level:'bad', msg:'Not a Handshake token'};
    const [, p, asn, sig] = parts; let pl;
    try { pl = JSON.parse(td.decode(ub64u(p))); } catch { return {ok:false, level:'bad', msg:'Malformed payload'}; }
    const raw = ub64u(pl.pub);
    let good = false; try { good = await ecVerify(raw, ub64u(sig), te.encode(`HHT1.${p}.${asn}`)); } catch {}
    if (!good) return {ok:false, level:'bad', msg:'INVALID signature: token forged or altered'};
    if (now > pl.exp * 1000) return {ok:false, level:'bad', msg:'Signature valid but token EXPIRED', pl};
    if (pl.iat * 1000 > now + 120000) return {ok:false, level:'bad', msg:'Issued in the future', pl};
    let pk = null;
    if (asn) {
      const a = JSON.parse(td.decode(ub64u(asn)));
      pk = await verifyAssertion(a, await sha(`HHT1.${p}`));
      if (!pk.ok) return {ok:false, level:'bad', msg:'Passkey check failed: ' + pk.why, pl};
      if (pl.pk && pl.pk !== await fp(ub64u(a.spki))) return {ok:false, level:'bad', msg:'Passkey does not match signer', pl};
    }
    const f = await fp(raw); const c = contacts.find(c => c.fp === f);
    if (!c) return {ok:false, level:'warn', msg:`Signature is valid, but the key ${f} is NOT one of your paired contacts. Anyone can make a key: don't trust the name "${pl.n}".`, pl};
    if (c.pk && pk === null) return {ok:false, level:'warn', msg:`Signed by ${c.name}'s device, but WITHOUT the passkey they bound: no proof of user verification.`, pl};
    return {ok:true, level:'ok', msg:`VERIFIED: signed by ${c.name}'s paired device key (${f})` + (pk ? (pk.uv ? ', and a passkey with user verification approved it' : ', passkey present (no UV)') : '') + '.', pl, contact:c};
  }
  return {b64u, ub64u, rand, sha, fp, code, checkCode, respond, newChallenge, genIdentity, rawPub, ecSign, ecVerify, verifyAssertion, verifyToken, win, STEP, te, td};
})();
