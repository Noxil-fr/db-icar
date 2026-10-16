// Chiffre source.html (en clair, non versionné) vers index.html (publié).
// Usage : node build.mjs            -> demande le mot de passe
//         DBICAR_PASSWORD=... node build.mjs
// Chiffrement : gzip + AES-256-GCM, clé dérivée par PBKDF2-SHA256.
import { readFileSync, writeFileSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { randomBytes, pbkdf2Sync, createCipheriv } from 'node:crypto';

const SRC = 'source.html';
const OUT = 'index.html';
const ITERATIONS = 600000;

function askHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    if (!stdin.isTTY) {
      let data = '';
      stdin.on('data', (c) => (data += c));
      stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')));
      return;
    }
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let pwd = '';
    const onData = (ch) => {
      if (ch === '\r' || ch === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.off('data', onData);
        process.stdout.write('\n');
        resolve(pwd);
      } else if (ch === '\u0003') {
        process.exit(1);
      } else if (ch === '\u0008' || ch === '\u007f') {
        if (pwd.length) { pwd = pwd.slice(0, -1); process.stdout.write('\b \b'); }
      } else {
        pwd += ch;
        process.stdout.write('*'.repeat(ch.length));
      }
    };
    stdin.on('data', onData);
  });
}

async function getPassword() {
  if (process.env.DBICAR_PASSWORD) return process.env.DBICAR_PASSWORD;
  const p1 = await askHidden('Mot de passe : ');
  const p2 = await askHidden('Confirmer    : ');
  if (p1 !== p2) { console.error('Les mots de passe ne correspondent pas.'); process.exit(1); }
  return p1;
}

const password = await getPassword();
if (password.length < 8) { console.error('Mot de passe trop court (8 caractères minimum).'); process.exit(1); }

const plain = gzipSync(readFileSync(SRC));
const salt = randomBytes(16);
const iv = randomBytes(12);
const key = pbkdf2Sync(password, salt, ITERATIONS, 32, 'sha256');
const cipher = createCipheriv('aes-256-gcm', key, iv);
// WebCrypto attend le tag GCM collé à la fin du texte chiffré
const data = Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);

const payload = JSON.stringify({
  v: 1,
  iter: ITERATIONS,
  salt: salt.toString('base64'),
  iv: iv.toString('base64'),
  data: data.toString('base64'),
});

const page = `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>DB I'CAR DMS</title>
<style>
:root{--bg:#0f1117;--bg2:#1a1d27;--bg3:#21253a;--border:#2a2f45;--text:#f1f5f9;--text3:#a3b1c6;--accent:#3B82F6;--err:#f87171}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
form{width:100%;max-width:340px;background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px 24px;display:flex;flex-direction:column;gap:14px;box-shadow:0 12px 32px rgba(0,0,0,.4)}
.logo{font-size:15px;font-weight:700;color:var(--accent);letter-spacing:.08em}
p{font-size:14px;color:var(--text3)}
input[type=password]{width:100%;background:var(--bg3);border:1px solid var(--border);border-radius:7px;padding:10px 12px;color:var(--text);font-size:15px;outline:none}
input[type=password]:focus{border-color:var(--accent)}
label{display:flex;align-items:center;gap:8px;font-size:13px;color:var(--text3);cursor:pointer}
button{background:var(--accent);color:#fff;border:none;border-radius:7px;padding:10px;font-size:15px;font-weight:600;cursor:pointer}
button:disabled{opacity:.6;cursor:wait}
.err{font-size:13px;color:var(--err);min-height:18px}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <div class="logo">DB I'CAR DMS</div>
  <p>Cette page est protégée. Saisissez le mot de passe.</p>
  <input type="password" id="pwd" autocomplete="current-password" autofocus required>
  <label><input type="checkbox" id="remember"> Se souvenir sur cet appareil</label>
  <button id="btn" type="submit">Ouvrir</button>
  <div class="err" id="err"></div>
</form>
<script>
(()=>{
const P=${payload};
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const STORE='dbicar-key';
async function deriveKey(pwd){
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(pwd),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt:b64(P.salt),iterations:P.iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},true,['decrypt']);
}
async function show(buf){
  const html=await new Response(new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  document.open();document.write(html);document.close();
}
function saved(){try{return localStorage.getItem(STORE)||sessionStorage.getItem(STORE)}catch(e){return null}}
function save(raw,remember){try{(remember?localStorage:sessionStorage).setItem(STORE,raw)}catch(e){}}
function forget(){try{localStorage.removeItem(STORE);sessionStorage.removeItem(STORE)}catch(e){}}
(async()=>{
  const raw=saved();
  if(raw){
    try{const key=await crypto.subtle.importKey('raw',b64(raw),'AES-GCM',false,['decrypt']);await show(await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(P.iv)},key,b64(P.data)));return}
    catch(e){forget()}
  }
})();
document.getElementById('f').addEventListener('submit',async e=>{
  e.preventDefault();
  const btn=document.getElementById('btn'),err=document.getElementById('err');
  btn.disabled=true;err.textContent='';
  try{
    const key=await deriveKey(document.getElementById('pwd').value);
    const raw=new Uint8Array(await crypto.subtle.exportKey('raw',key));
    const buf=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64(P.iv)},key,b64(P.data));
    save(btoa(String.fromCharCode(...raw)),document.getElementById('remember').checked);
    await show(buf);
  }catch(ex){
    err.textContent='Mot de passe incorrect.';btn.disabled=false;
    document.getElementById('pwd').select();
  }
});
})();
</script>
</body>
</html>
`;

writeFileSync(OUT, page);
console.log(`${OUT} généré (${(page.length / 1024).toFixed(0)} Ko, source ${(readFileSync(SRC).length / 1024).toFixed(0)} Ko).`);
