const p = require('puppeteer-core');
const R = []; const ck = (n, c) => { R.push(`${c ? 'PASS' : 'FAIL'}  ${n}`); };
(async () => {
  const b = await p.launch({ executablePath: '/usr/bin/google-chrome', headless: 'new', args: ['--no-sandbox'] });
  const U = 'http://localhost:8765/';
  const mk = async name => { const ctx = await b.createBrowserContext(); const pg = await ctx.newPage(); await pg.setViewport({width:1000,height:900});
    pg.on('pageerror', e => R.push('PAGEERROR ' + name + ' ' + e.message)); await pg.goto(U); await pg.waitForFunction(() => document.getElementById('me').textContent.includes('fingerprint'));
    await pg.$eval('#myName', (e, n) => e.value = n, name); await pg.click('#saveName'); return pg; };
  const A = await mk('Alice (CFO)'), B = await mk('Bob (Finance)'), M = await mk('Mallory');
  // Alice binds passkey via virtual authenticator
  const cdp = await A.createCDPSession(); await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true } });
  await A.click('#regPasskey'); await A.waitForFunction(() => document.getElementById('me').textContent.includes('passkey'));
  ck('Passkey (WebAuthn) registration', true);
  const val = (pg, s) => pg.$eval(s, e => e.value), txt = (pg, s) => pg.$eval(s, e => e.textContent);
  const set = (pg, s, v) => pg.$eval(s, (e, v) => e.value = v, v);
  // Pair A<->B
  await A.click('#mkPair'); const code = await val(A, '#pairOut');
  await set(B, '#pairIn', code); await B.click('#importPair'); const reply = await val(B, '#pairOut');
  await set(A, '#pairIn', reply); await A.click('#importPair');
  ck('Pairing A->B->A', (await txt(A, '#contacts')).includes('Bob') && (await txt(B, '#contacts')).includes('Alice'));
  // Mallory pairs with Bob separately (different key/secret) -> to forge
  await M.click('#mkPair'); const mcode = await val(M, '#pairOut');
  await new Promise(r => setTimeout(r, 1200));
  for (const pg of [A,B]) await (await pg.$$('nav button'))[1].click();
  // Rotating codes
  const aCode = await txt(A, '#myCode'), bCode = await txt(B, '#myCode');
  ck(`Codes are direction-bound (A=${aCode}, B=${bCode} differ)`, aCode !== bCode && /^\d{6}$/.test(aCode));
  await set(B, '#peerCode', aCode); await B.click('#checkCode'); await new Promise(r => setTimeout(r, 200));
  const r1 = await txt(B, '#codeRes'); ck('Bob verifies Alice\'s correct code -> MATCH', r1.includes('MATCH') && !r1.includes('NO'));
  await set(B, '#peerCode', bCode); await B.click('#checkCode'); await new Promise(r => setTimeout(r, 200));
  ck('Reflected (Bob\'s own) code rejected', (await txt(B, '#codeRes')).includes('NO MATCH'));
  const forged = String((+aCode + 1) % 1e6).padStart(6, '0');
  await set(B, '#peerCode', forged); await B.click('#checkCode'); await new Promise(r => setTimeout(r, 200));
  ck('Wrong/guessed code rejected', (await txt(B, '#codeRes')).includes('NO MATCH'));
  // Challenge-response
  await B.click('#newChal'); const ch = await txt(B, '#chal');
  await set(A, '#theirChal', ch); await A.click('#answer'); await A.waitForFunction(() => document.getElementById('myResp').textContent.length === 6);
  await set(B, '#chalResp', await txt(A, '#myResp')); await B.click('#checkResp'); await new Promise(r => setTimeout(r, 200));
  ck('Challenge-response correct key -> pass', (await txt(B, '#respRes')).includes('Correct'));
  // Mallory (wrong key: she imports her own pairing as a "fake Alice" into a 4th context) -> answer is wrong
  const X = await mk('Fake Alice'); await set(X, '#pairIn', mcode); await X.click('#importPair'); await new Promise(r => setTimeout(r, 300)); await (await X.$$('nav button'))[1].click();
  await set(X, '#theirChal', ch); await X.click('#answer'); await X.waitForFunction(() => document.getElementById('myResp').textContent.length === 6);
  await set(B, '#chalResp', await txt(X, '#myResp')); await B.click('#checkResp'); await new Promise(r => setTimeout(r, 200));
  ck('Challenge-response wrong key -> fail', (await txt(B, '#respRes')).includes('Wrong'));
  // Tokens
  const tabs = async pg => (await pg.$$('nav button'))[2].click();
  await tabs(A); await tabs(B); await tabs(M);
  await A.click('#sign'); await A.waitForFunction(() => document.getElementById('tokOut').value.startsWith('HHT1'));
  const tok = await val(A, '#tokOut'); ck('Token carries passkey assertion', tok.split('.')[2].length > 50);
  const verify = async (pg, t) => { await set(pg, '#tokIn', t); await pg.click('#verifyTok'); await new Promise(r => setTimeout(r, 400)); return txt(pg, '#tokRes'); };
  let r = await verify(B, tok); ck('Bob verifies Alice\'s passkey-backed token -> VERIFIED', r.includes('VERIFIED') && r.includes('user verification'));
  const [h, pl, asn, sig] = tok.split('.'); const o = JSON.parse(Buffer.from(pl, 'base64url')); o.msg = 'Wire $25,000,000 to account 666';
  const tampered = [h, Buffer.from(JSON.stringify(o)).toString('base64url'), asn, sig].join('.');
  r = await verify(B, tampered); ck('Tampered statement -> INVALID', r.includes('INVALID'));
  r = await verify(B, [h, pl, '', sig].join('.')); ck('Stripped passkey assertion -> INVALID', r.includes('INVALID'));
  await M.evaluate(() => localStorage.setItem('hh.name', JSON.stringify('Alice (CFO)'))); await M.click('#sign'); await M.waitForFunction(() => document.getElementById('tokOut').value.startsWith('HHT1'));
  r = await verify(B, await val(M, '#tokOut')); ck('Mallory\'s token claiming "Alice (CFO)" -> NOT a paired contact', r.includes('NOT one of your paired'));
  r = await verify(B, 'HHT1.garbage.x.y'); ck('Garbage token rejected', r.includes('Malformed') || r.includes('INVALID'));
  // Screenshot: Bob verified view
  await verify(B, tok); await B.evaluate(() => window.scrollTo(0, 0));
  await B.screenshot({ path: '/workspace/humanhandshake-local.png', fullPage: true });
  await b.close(); console.log(R.join('\n'));
})().catch(e => { console.log(R.join('\n')); console.error(e); process.exit(1); });
