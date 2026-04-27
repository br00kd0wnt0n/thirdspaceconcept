const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SITE_PASSWORD = process.env.SITE_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET ||
  (SITE_PASSWORD
    ? crypto.createHash('sha256').update(SITE_PASSWORD + ':thirdspace').digest('hex')
    : 'dev-secret-not-for-prod');
const SESSION_DAYS = 7;
const COOKIE_NAME = 'thirdspace_session';
const root = __dirname;

const types = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
};

function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}

function makeToken() {
  const exp = Date.now() + SESSION_DAYS * 86400 * 1000;
  return `${exp}.${sign(String(exp))}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return false;
  const [exp, sig] = token.split('.');
  if (!exp || !sig) return false;
  const expected = sign(exp);
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  return Number(exp) > Date.now();
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function pwEqual(a, b) {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Thirdspace — Enter</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght,SOFT,WONK@9..144,300..900,0..100,0..1&family=Geist:wght@300..700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #0a0808;
    --bg-2: #120e0e;
    --ink: #ece6df;
    --ink-muted: #8a817a;
    --ink-dim: #5a524c;
    --accent: #e63860;
    --ember: #f2a23a;
    --rule: #2a2220;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background:
      radial-gradient(1200px 600px at 20% 10%, rgba(230,56,96,0.10), transparent 60%),
      radial-gradient(900px 500px at 80% 90%, rgba(242,162,58,0.08), transparent 60%),
      var(--bg);
    color: var(--ink);
    font-family: 'Geist', sans-serif;
    display: grid;
    place-items: center;
    padding: 24px;
  }
  .card {
    width: 100%;
    max-width: 420px;
    background: linear-gradient(180deg, var(--bg-2), var(--bg));
    border: 1px solid var(--rule);
    border-radius: 18px;
    padding: 40px 36px 32px;
    box-shadow: 0 30px 80px -20px rgba(0,0,0,0.6);
  }
  .eyebrow {
    font-family: 'Geist', sans-serif;
    font-size: 11px;
    letter-spacing: 0.22em;
    text-transform: uppercase;
    color: var(--ember);
    margin-bottom: 18px;
  }
  h1 {
    font-family: 'Fraunces', serif;
    font-weight: 400;
    font-variation-settings: "SOFT" 50, "WONK" 1;
    font-size: 38px;
    line-height: 1.05;
    letter-spacing: -0.01em;
    margin-bottom: 8px;
  }
  h1 em {
    font-style: italic;
    color: var(--accent);
    font-variation-settings: "SOFT" 100, "WONK" 1;
  }
  p.lede {
    color: var(--ink-muted);
    font-size: 14px;
    line-height: 1.5;
    margin-bottom: 28px;
  }
  form { display: flex; flex-direction: column; gap: 14px; }
  label {
    font-size: 11px;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: var(--ink-dim);
  }
  input[type="password"] {
    background: rgba(255,255,255,0.02);
    border: 1px solid var(--rule);
    border-radius: 10px;
    padding: 14px 16px;
    color: var(--ink);
    font-family: 'Geist', sans-serif;
    font-size: 15px;
    outline: none;
    transition: border-color 0.2s, background 0.2s;
  }
  input[type="password"]:focus {
    border-color: var(--accent);
    background: rgba(230,56,96,0.04);
  }
  button {
    margin-top: 6px;
    background: var(--accent);
    color: var(--bg);
    border: none;
    border-radius: 10px;
    padding: 14px 16px;
    font-family: 'Geist', sans-serif;
    font-weight: 600;
    font-size: 14px;
    letter-spacing: 0.04em;
    cursor: pointer;
    transition: background 0.2s, transform 0.05s;
  }
  button:hover { background: #f04a72; }
  button:active { transform: translateY(1px); }
  .error {
    color: var(--accent);
    font-size: 13px;
    margin-top: 4px;
    min-height: 18px;
  }
  .foot {
    margin-top: 28px;
    padding-top: 18px;
    border-top: 1px solid var(--rule);
    color: var(--ink-dim);
    font-size: 11px;
    letter-spacing: 0.14em;
    text-transform: uppercase;
  }
</style>
</head>
<body>
  <main class="card">
    <div class="eyebrow">Rock Academy</div>
    <h1>Third<em>space</em></h1>
    <p class="lede">A private preview. Enter the password to continue.</p>
    <form method="POST" action="/auth" autocomplete="off">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autofocus required />
      <div class="error">${error ? escapeHtml(error) : ''}</div>
      <button type="submit">Enter</button>
    </form>
    <div class="foot">Concept · Confidential</div>
  </main>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);

  if (urlPath === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }

  const cookies = parseCookies(req.headers.cookie);
  const authed = verifyToken(cookies[COOKIE_NAME]);

  if (urlPath === '/login' && req.method === 'GET') {
    if (authed) {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(loginPage());
  }

  if (urlPath === '/auth' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 4096) req.destroy();
    });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const pw = params.get('password') || '';
      if (!SITE_PASSWORD) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end('SITE_PASSWORD env var not configured');
      }
      if (!pwEqual(pw, SITE_PASSWORD)) {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(loginPage('Wrong password'));
      }
      const cookie = [
        `${COOKIE_NAME}=${makeToken()}`,
        'HttpOnly',
        'Path=/',
        `Max-Age=${SESSION_DAYS * 86400}`,
        'SameSite=Lax',
        'Secure',
      ].join('; ');
      res.writeHead(302, { 'Set-Cookie': cookie, Location: '/' });
      res.end();
    });
    return;
  }

  if (urlPath === '/logout') {
    const cookie = `${COOKIE_NAME}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`;
    res.writeHead(302, { 'Set-Cookie': cookie, Location: '/login' });
    return res.end();
  }

  if (SITE_PASSWORD && !authed) {
    res.writeHead(302, { Location: '/login' });
    return res.end();
  }

  let relPath = urlPath;
  if (relPath === '/' || relPath === '') relPath = '/index.html';
  const filePath = path.join(root, relPath);
  if (!filePath.startsWith(root)) {
    res.writeHead(403);
    return res.end('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const type = types[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'private, max-age=300' });
    res.end(data);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`thirdspace listening on 0.0.0.0:${PORT} (auth=${SITE_PASSWORD ? 'on' : 'off'})`);
});

process.on('uncaughtException', (err) => console.error('uncaughtException', err));
process.on('unhandledRejection', (err) => console.error('unhandledRejection', err));
