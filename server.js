'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const DB = process.env.KEY_STORE || path.join(__dirname, 'data', 'keys.json');
if (ADMIN_PASSWORD.length < 16) {
  console.error('ERRO: defina ADMIN_PASSWORD com pelo menos 16 caracteres nas variáveis de ambiente.');
  process.exit(1);
}
const durations = { '1h': 3600000, '1d': 86400000, '3d': 259200000, '7d': 604800000, '30d': 2592000000, 'perm': null };
const rate = new Map();
function rateLimit(req, res) {
  const ip = req.socket.remoteAddress || 'unknown';
  const now = Date.now(); let item = rate.get(ip);
  if (!item || now - item.start > 60000) item = { start: now, count: 0 };
  item.count++; rate.set(ip, item);
  if (rate.size > 5000) for (const [k,v] of rate) if (now-v.start > 60000) rate.delete(k);
  if (item.count > 120) { send(res, 429, { error: 'Muitas tentativas. Aguarde um minuto.' }); return false; }
  return true;
}
function load() { try { const x = JSON.parse(fs.readFileSync(DB, 'utf8')); return Array.isArray(x) ? x : []; } catch { return []; } }
function save(items) { fs.mkdirSync(path.dirname(DB), { recursive: true }); const tmp = DB + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(items, null, 2), { mode: 0o600 }); fs.renameSync(tmp, DB); }
function send(res, status, obj) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'" }); res.end(JSON.stringify(obj)); }
function body(req) { return new Promise((resolve, reject) => { let s = ''; req.on('data', c => { s += c; if (s.length > 12000) { reject(new Error('body too large')); req.destroy(); } }); req.on('end', () => { try { resolve(JSON.parse(s || '{}')); } catch { reject(new Error('invalid json')); } }); req.on('error', reject); }); }
function authorized(req) { const supplied = String(req.headers['x-admin-password'] || ''); const a = Buffer.from(supplied); const b = Buffer.from(ADMIN_PASSWORD); return a.length === b.length && crypto.timingSafeEqual(a, b); }
function makeKey(prefix) { const chunk = () => crypto.randomBytes(4).toString('hex').toUpperCase(); return `${prefix}-${chunk()}-${chunk()}-${chunk()}`; }
function servePage(res, name) { const p = path.join(__dirname, 'public', name); fs.readFile(p, (e, data) => { if (e) return send(res, 404, { error: 'Página não encontrada.' }); res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY' }); res.end(data); }); }
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!rateLimit(req, res)) return;
  if (req.method === 'GET' && ['/', '/auxilio'].includes(url.pathname)) return servePage(res, 'auxilio.html');
  if (req.method === 'GET' && url.pathname === '/gerador') return servePage(res, 'gerador.html');
  if (req.method === 'GET' && url.pathname === '/health') return send(res, 200, { ok: true, service: 'VTZIM key service' });
  if (req.method !== 'POST' || !['/api/validate','/api/generate','/api/list','/api/revoke'].includes(url.pathname)) return send(res, 404, { error: 'Não encontrado.' });
  let b; try { b = await body(req); } catch { return send(res, 400, { error: 'Pedido inválido.' }); }
  if (url.pathname === '/api/validate') {
    const key = String(b.key || '').trim().toUpperCase().slice(0, 100);
    if (!key) return send(res, 200, { valid: false, message: 'Digite uma chave.' });
    const item = load().find(x => x.key === key);
    if (!item) return send(res, 200, { valid: false, message: 'Chave inválida.' });
    if (item.revoked) return send(res, 200, { valid: false, message: 'Esta chave foi revogada.' });
    if (item.expiresAt !== null && item.expiresAt !== undefined && Date.now() >= item.expiresAt) return send(res, 200, { valid: false, message: 'Esta chave expirou.' });
    return send(res, 200, { valid: true, message: 'Chave válida.', expiresAt: item.expiresAt, permanent: item.expiresAt === null });
  }
  if (!authorized(req)) return send(res, 401, { error: 'Senha de administrador incorreta.' });
  if (url.pathname === '/api/generate') {
    if (!(b.duration in durations)) return send(res, 400, { error: 'Validade inválida.' });
    const prefix = String(b.prefix || 'VTZIM').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12) || 'VTZIM';
    const all = load(); let key;
    do { key = makeKey(prefix); } while (all.some(x => x.key === key));
    const duration = durations[b.duration]; const expiresAt = duration === null ? null : Date.now() + duration;
    all.unshift({ key, createdAt: Date.now(), expiresAt, revoked: false, duration: b.duration }); save(all);
    return send(res, 200, { key, expiresAt, permanent: duration === null });
  }
  if (url.pathname === '/api/list') return send(res, 200, { keys: load().map(x => ({ ...x, status: x.revoked ? 'Revogada' : (x.expiresAt !== null && x.expiresAt !== undefined && Date.now() >= x.expiresAt ? 'Expirada' : 'Ativa') })) });
  if (url.pathname === '/api/revoke') {
    const all = load(); const item = all.find(x => x.key === String(b.key || '').trim().toUpperCase());
    if (!item) return send(res, 404, { error: 'Chave não encontrada.' });
    item.revoked = true; save(all); return send(res, 200, { ok: true });
  }
});
server.listen(PORT, '0.0.0.0', () => console.log(`VTZIM server ouvindo na porta ${PORT}`));
