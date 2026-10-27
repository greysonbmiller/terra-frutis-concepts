/* Terra Frutis design preview: serves the encrypted files of this site, decrypted in the browser. */
'use strict';
const te = new TextEncoder();
const HKDF_SALT = 'tf-preview hkdf v1';
const TYPES = {
  html: 'text/html; charset=utf-8', htm: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8',
  js: 'text/javascript; charset=utf-8', mjs: 'text/javascript; charset=utf-8', json: 'application/json',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp',
  avif: 'image/avif', gif: 'image/gif', ico: 'image/x-icon', woff2: 'font/woff2', woff: 'font/woff',
  ttf: 'font/ttf', otf: 'font/otf', pdf: 'application/pdf', txt: 'text/plain; charset=utf-8',
  md: 'text/plain; charset=utf-8', xml: 'application/xml', webmanifest: 'application/manifest+json',
  mp4: 'video/mp4', webm: 'video/webm',
};
const typeOf = p => TYPES[(p.split('/').pop().split('.').pop() || '').toLowerCase()] || 'application/octet-stream';

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

let dbP = null;
let keys = null;
function db() {
  if (!dbP) {
    dbP = new Promise((resolve, reject) => {
      const r = indexedDB.open('tf-preview', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('keys');
      r.onsuccess = () => {
        const d = r.result;
        d.onversionchange = () => { d.close(); dbP = null; keys = null; };
        resolve(d);
      };
      r.onerror = () => { dbP = null; reject(r.error); };
    });
  }
  return dbP;
}
async function getKeys() {
  if (keys) return keys;
  try {
    const d = await db();
    keys = await new Promise(resolve => {
      const q = d.transaction('keys', 'readonly').objectStore('keys').get('k');
      q.onsuccess = () => resolve(q.result || null);
      q.onerror = () => resolve(null);
    });
  } catch (e) { keys = null; }
  return keys;
}
async function clearKeys() {
  keys = null;
  try {
    const d = await db();
    await new Promise(resolve => {
      const t = d.transaction('keys', 'readwrite');
      t.objectStore('keys').delete('k');
      t.oncomplete = t.onerror = t.onabort = () => resolve();
    });
  } catch (e) { /* nothing stored */ }
}
self.addEventListener('message', e => { if (e.data === 'lock') keys = null; });

const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
async function binPath(k, p) {
  const n = hex(await crypto.subtle.sign('HMAC', k.name, te.encode('name:' + p))).slice(0, 24);
  return 'c/' + n.slice(0, 2) + '/' + n.slice(2) + '.bin';
}
/* The decrypted bytes of the site file at path p, null if there is none, or 'bad' if it does not decrypt. */
async function open(k, base, p, signal) {
  const res = await fetch(base + await binPath(k, p), { cache: 'no-cache', signal });
  if (!res.ok) return null;
  const buf = new Uint8Array(await res.arrayBuffer());
  try {
    return await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12), additionalData: te.encode(p) }, k.enc, buf.slice(12));
  } catch (e) { return 'bad'; }
}
async function keysWork(k, base) {
  const r = await open(k, base, '__check');
  return r instanceof ArrayBuffer && new TextDecoder().decode(r) === 'tf-preview-check-v1';
}

async function notFound(k, base, rel) {
  const page = rel.startsWith('a/') ? 'a/404/' : rel.startsWith('d/') ? 'd/404/' : '404/';
  const body = await open(k, base, page + 'index.html');
  if (!(body instanceof ArrayBuffer)) return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  /* The page's relative links are written for its own folder. */
  const html = new TextDecoder().decode(body).replace(/<head([^>]*)>/i, '<head$1><base href="' + base + page + '">');
  return new Response(html, { status: 404, headers: { 'Content-Type': TYPES.html, 'Cache-Control': 'no-store' } });
}

/* Stored keys that don't open this site: clear them, retire this worker, and let the network answer
   (the unlock page). */
async function forget(req) {
  await clearKeys();
  try { await self.registration.unregister(); } catch (e) { /* already gone */ }
  return fetch(req);
}

async function handle(req, url, rel, base) {
  const k = await getKeys();
  if (!k) return fetch(req);
  let p = rel;
  if (p === '' || p.endsWith('/')) p += 'index.html';
  let body = await open(k, base, p, req.signal);
  if (body === 'bad') {
    if (!(await keysWork(k, base))) return forget(req);
    return new Response('This file could not be opened.', { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  if (body === null && !/\.[A-Za-z0-9]+$/.test(p.split('/').pop())) {
    const dir = await open(k, base, p + '/index.html');
    if (dir instanceof ArrayBuffer) return Response.redirect(url.origin + url.pathname + '/' + url.search, 301);
  }
  if (body === null) {
    if (req.mode === 'navigate') {
      /* Keys from another password or salt find no file at all: forget them and show the unlock page. */
      if (!(await keysWork(k, base))) return forget(req);
      return notFound(k, base, rel);
    }
    return new Response('Not found', { status: 404, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  return new Response(body, { status: 200, headers: { 'Content-Type': typeOf(p), 'Cache-Control': 'no-store' } });
}

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  const base = new URL(self.registration.scope).pathname;
  if (!url.pathname.startsWith(base)) return;
  let rel;
  try { rel = decodeURIComponent(url.pathname.slice(base.length)); } catch (err) { return; }
  if (rel === 'sw.js' || rel.startsWith('c/')) return;
  /* A request the page gave up on (it navigated away) is answered quietly instead of failing loudly. */
  e.respondWith(handle(req, url, rel, base).catch(() => (req.signal && req.signal.aborted
    ? new Response(null, { status: 204 }) : fetch(req).catch(() => new Response(null, { status: 204 })))));
});
