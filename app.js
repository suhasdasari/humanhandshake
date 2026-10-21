// Handshake UI. All state lives in this browser (IndexedDB + localStorage).
const $ = id => document.getElementById(id);
const LS = { get: (k, d) => JSON.parse(localStorage.getItem('hh.' + k) || JSON.stringify(d)), set: (k, v) => localStorage.setItem('hh.' + k, JSON.stringify(v)) };
const enc = o => HH.b64u(HH.te.encode(JSON.stringify(o)));
const dec = s => JSON.parse(HH.td.decode(HH.ub64u(s)));
let ID; // {priv, pub(raw), fp}

function idb(op, val) {
  return new Promise((res, rej) => {
    const r = indexedDB.open('handshake', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('k');
    r.onsuccess = () => { const tx = r.result.transaction('k', op ? 'readwrite' : 'readonly'); const st = tx.objectStore('k');
      const q = op ? st.put(val, 'id') : st.get('id'); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); };
    r.onerror = () => rej(r.error);
  });
}
async function loadIdentity() {
  let kp = await idb();
  if (!kp) { kp = await HH.genIdentity(); await idb(true, kp); }
  const pub = await HH.rawPub(kp.publicKey);
  ID = { priv: kp.privateKey, pub, fp: await HH.fp(pub) };
}
const contacts = () => LS.get('contacts', []);
const passkey = () => LS.get('passkey', null);
function msg(el, text, level) { el.textContent = text; el.className = 'msg ' + (level === 'ok' ? 'ok' : level === 'warn' ? 'warnc' : level === 'bad' ? 'bad' : ''); }

function render() {
  const name = LS.get('name', '');
  $('myName').value = name;
  const pk = passkey();
  $('me').textContent = `Your key fingerprint: ${ID.fp}${name ? ' · ' + name : ''}${pk ? ' · passkey bound' : ''}`;
  $('pkStatus').textContent = pk ? `Passkey bound (${pk.fp}). Tokens you sign will need your fingerprint, face or PIN.` : (window.PublicKeyCredential ? 'Optional: binding a passkey adds a user-verification step to every token you sign.' : 'This browser does not support WebAuthn.');
  const cs = contacts();
  $('contacts').innerHTML = cs.length ? '' : '<li class="muted">No contacts yet</li>';
  $('callContact').innerHTML = cs.length ? '' : '<option value="">Pair with someone first</option>';
  cs.forEach((c, i) => {
    const li = document.createElement('li'); li.textContent = `${c.name}: key ${c.fp}${c.pk ? ' · passkey' : ''}${c.secret ? '' : ' (waiting for their reply)'}`; $('contacts').append(li);
    if (c.secret) { const o = document.createElement('option'); o.value = i; o.textContent = `${c.name} (${c.fp})`; $('callContact').append(o); }
  });
}
const current = () => { const c = contacts()[$('callContact').value]; return c && { ...c, s: HH.ub64u(c.secret) }; };
function upsert(c) { const cs = contacts().filter(x => x.fp !== c.fp); cs.push(c); LS.set('contacts', cs); }

// Tabs
document.querySelectorAll('nav button').forEach(b => b.onclick = () => {
  document.querySelectorAll('nav button').forEach(x => x.classList.toggle('on', x === b));
  document.querySelectorAll('main section').forEach(s => s.hidden = s.id !== b.dataset.t);
});

$('saveName').onclick = () => { LS.set('name', $('myName').value.trim()); render(); };

$('regPasskey').onclick = async () => {
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      challenge: HH.rand(32), rp: { name: 'Handshake' },
      user: { id: HH.rand(16), name: LS.get('name', '') || 'handshake-user', displayName: LS.get('name', '') || 'Handshake user' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 60000 } });
    const spki = new Uint8Array(cred.response.getPublicKey());
    LS.set('passkey', { id: HH.b64u(cred.rawId), spki: HH.b64u(spki), fp: await HH.fp(spki) });
    render(); msg($('pairMsg'), 'Passkey bound. If you have already paired, pair again so your contacts learn about it.', 'ok');
  } catch (e) { msg($('pairMsg'), 'Passkey registration failed: ' + e.message, 'bad'); }
};

$('mkPair').onclick = () => {
  const secret = HH.b64u(HH.rand(32)), id = HH.b64u(HH.rand(6));
  const pend = LS.get('pending', {}); pend[id] = secret; LS.set('pending', pend);
  $('pairOut').value = 'HHP1.' + enc({ n: LS.get('name', '') || 'Unnamed', pub: HH.b64u(ID.pub), pk: passkey()?.fp, s: secret, id });
  msg($('pairMsg'), 'Give this code to the other person over a channel you trust. It contains a SECRET, so never post it in public.', 'warn');
};
$('importPair').onclick = async () => {
  try {
    const t = $('pairIn').value.trim(); const [kind, body] = t.split('.'); const o = dec(body);
    const pub = HH.ub64u(o.pub); if (pub.length !== 65) throw Error('bad key');
    const fp = await HH.fp(pub);
    if (fp === ID.fp) throw Error('That is your own code');
    if (kind === 'HHP1') {
      upsert({ name: o.n, fp, pub: o.pub, pk: o.pk || null, secret: o.s });
      $('pairOut').value = 'HHR1.' + enc({ n: LS.get('name', '') || 'Unnamed', pub: HH.b64u(ID.pub), pk: passkey()?.fp, id: o.id });
      msg($('pairMsg'), `Paired with ${o.n} (${fp}). Send them the reply code above.`, 'ok');
    } else if (kind === 'HHR1') {
      const pend = LS.get('pending', {}); if (!pend[o.id]) throw Error('No matching pairing code was created on this device');
      upsert({ name: o.n, fp, pub: o.pub, pk: o.pk || null, secret: pend[o.id] }); delete pend[o.id]; LS.set('pending', pend);
      msg($('pairMsg'), `Paired with ${o.n} (${fp}).`, 'ok');
    } else throw Error('Unknown code type');
    $('pairIn').value = ''; render();
  } catch (e) { msg($('pairMsg'), 'Import failed: ' + e.message, 'bad'); }
};

// Live call
async function tick() {
  const c = current(); const left = HH.STEP - (Date.now() / 1000) % HH.STEP;
  $('bar').style.width = (left / HH.STEP * 100) + '%';
  $('myCode').textContent = c ? await HH.code(c.s, ID.fp) : '——————';
}
setInterval(tick, 1000);
$('callContact').onchange = tick;
$('checkCode').onclick = async () => {
  const c = current(); if (!c) return msg($('codeRes'), 'Pair first', 'bad');
  const ok = await HH.checkCode(c.s, c.fp, $('peerCode').value.trim());
  msg($('codeRes'), ok ? `✔ MATCH: they hold ${c.name}'s key.` : `✘ NO MATCH. This is not proof of a deepfake, but don't proceed. Hang up and call back on a number you already know.`, ok ? 'ok' : 'bad');
};
$('newChal').onclick = () => { $('chal').textContent = HH.newChallenge(); msg($('respRes'), '', ''); };
$('checkResp').onclick = async () => {
  const c = current(); const ch = $('chal').textContent; if (!c || !ch) return msg($('respRes'), 'Pair first and create a challenge', 'bad');
  const ok = (await HH.respond(c.s, c.fp, ch)) === $('chalResp').value.trim();
  msg($('respRes'), ok ? `✔ Correct response: ${c.name}'s device answered.` : '✘ Wrong response.', ok ? 'ok' : 'bad');
};
$('answer').onclick = async () => { const c = current(); if (c && $('theirChal').value.trim()) $('myResp').textContent = await HH.respond(c.s, ID.fp, $('theirChal').value); };

// Tokens
$('sign').onclick = async () => {
  try {
    const now = Math.floor(Date.now() / 1000); const pk = passkey();
    const p = enc({ v: 1, n: LS.get('name', '') || 'Unnamed', pub: HH.b64u(ID.pub), pk: pk?.fp, iat: now, exp: now + +$('ttl').value, msg: $('stmt').value, nonce: HH.b64u(HH.rand(9)) });
    let asn = '';
    if (pk) {
      const a = await navigator.credentials.get({ publicKey: { challenge: await HH.sha(`HHT1.${p}`), allowCredentials: [{ type: 'public-key', id: HH.ub64u(pk.id) }], userVerification: 'required', timeout: 60000 } });
      asn = enc({ ad: HH.b64u(a.response.authenticatorData), cd: HH.b64u(a.response.clientDataJSON), sig: HH.b64u(a.response.signature), spki: pk.spki });
    }
    const sig = await HH.ecSign(ID.priv, HH.te.encode(`HHT1.${p}.${asn}`));
    $('tokOut').value = `HHT1.${p}.${asn}.${HH.b64u(sig)}`;
  } catch (e) { $('tokOut').value = 'Signing failed: ' + e.message; }
};
$('copyTok').onclick = () => navigator.clipboard.writeText($('tokOut').value);
$('verifyTok').onclick = async () => {
  const r = await HH.verifyToken($('tokIn').value, contacts());
  const el = $('tokRes'); msg(el, (r.ok ? '✔ ' : r.level === 'warn' ? '⚠ ' : '✘ ') + r.msg, r.level);
  if (r.pl) { const d = document.createElement('div'); d.className = 'muted'; d.textContent = `Statement: "${r.pl.msg}" · claimed name: ${r.pl.n} · issued ${new Date(r.pl.iat * 1000).toLocaleString()} · expires ${new Date(r.pl.exp * 1000).toLocaleString()}`; el.append(d); }
};

loadIdentity().then(() => { render(); tick(); }).catch(e => alert('Init failed: ' + e.message));
