/**
 * Cloudflare Worker — Rezervační systém pro auditní pohovory
 *
 * Potřebné Cloudflare secrets (nastavit přes wrangler nebo Dashboard):
 *   GOOGLE_CLIENT_EMAIL   – e-mail service accountu
 *   GOOGLE_PRIVATE_KEY    – RSA privátní klíč (PEM, s \n jako novými řádky)
 *   SHEETS_ID             – ID Google Sheets dokumentu
 *   AUTH_SECRET           – náhodný řetězec pro podpis session tokenů (min. 32 znaků)
 *   AUDITORKA_PASSWORDS   – JSON: {"id1":"pbkdf2:sůl:hash","id2":"pbkdf2:sůl:hash"}
 *   ALLOWED_ORIGIN        – URL webu (např. https://rezervace-pohovory.pages.dev)
 */

// ════════════════════════════════════════════════════════════════
// KONSTANTY
// ════════════════════════════════════════════════════════════════

const SHEET_AUDITORKY = 'Auditorky';
const SHEET_SLOTY     = 'Sloty';
const SHEET_REZERVACE = 'Rezervace';

// Sloupce jednotlivých listů (musí odpovídat pořadí v Google Sheets)
const COLS_AUDITORKY  = ['id','jmeno','slug','aktivni'];
const COLS_SLOTY      = ['id','auditorka_id','datum','cas_od','cas_do','typ','stav','poznamka_interni'];
const COLS_REZERVACE  = ['id','slot_id','auditorka_id','jmeno','email','telefon','poznamka','vytvoreno','stav'];

// Konstanty stavů
const STAV_VOLNY    = 'volny';
const STAV_OBSAZENY = 'obsazeny';
const STAV_ZRUSEN   = 'zrusen';
const REZ_POTVRZENO = 'potvrzeno';
const REZ_ZRUSENO   = 'zrušeno';

// ════════════════════════════════════════════════════════════════
// RATE LIMITER (in-memory, na Worker isolate)
// Pro produkci s velkou zátěží: nahradit Cloudflare KV
// ════════════════════════════════════════════════════════════════

const rateLimitMap = new Map();

function checkRateLimit(ip, action, maxReq = 10, windowMs = 60000) {
  const key = `${ip}:${action}`;
  const now = Date.now();
  const entry = rateLimitMap.get(key);

  if (!entry || now - entry.windowStart > windowMs) {
    rateLimitMap.set(key, { count: 1, windowStart: now });
    return true;
  }
  entry.count++;
  return entry.count <= maxReq;
}

// Čistí záznamy starší než 2 minuty (voláno náhodně, aby nezdržovalo requesty)
function cleanRateLimitMap() {
  const cutoff = Date.now() - 120000;
  for (const [key, e] of rateLimitMap) {
    if (e.windowStart < cutoff) rateLimitMap.delete(key);
  }
}

// ════════════════════════════════════════════════════════════════
// SECURITY HEADERS
// ════════════════════════════════════════════════════════════════

function secHeaders(allowedOrigin) {
  return {
    'Content-Security-Policy': "default-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Access-Control-Allow-Origin': allowedOrigin || '',
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token',
  };
}

function jsonResp(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

// ════════════════════════════════════════════════════════════════
// GOOGLE SHEETS — JWT & ACCESS TOKEN
// ════════════════════════════════════════════════════════════════

// Cache access tokenu (platí ~1 hodinu)
let _tokenCache = { token: null, expiry: 0 };

function b64url(buf) {
  // Převede ArrayBuffer na base64url string
  const bytes = new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}

function pemToBuffer(pem) {
  // Odstraní PEM hlavičky a dekóduje base64 → ArrayBuffer
  const b64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/-----BEGIN RSA PRIVATE KEY-----/g, '')
    .replace(/-----END RSA PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const buf = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

async function importPrivateKey(pem) {
  return crypto.subtle.importKey(
    'pkcs8',
    pemToBuffer(pem),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
}

async function getAccessToken(env) {
  // Vrátí cached token pokud stále platí
  if (_tokenCache.token && _tokenCache.expiry > Date.now()) return _tokenCache.token;

  const pem = (env.GOOGLE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: env.GOOGLE_CLIENT_EMAIL,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };

  // Sestavit a podepsat JWT (RS256)
  const hdr = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const pld = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const input = `${hdr}.${pld}`;

  const key = await importPrivateKey(pem);
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(input));
  const jwt = `${input}.${b64url(sig)}`;

  // Vyměnit JWT za access token
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });

  if (!r.ok) throw new Error(`Google OAuth error: ${await r.text()}`);

  const { access_token } = await r.json();
  _tokenCache = { token: access_token, expiry: Date.now() + 3_500_000 }; // 58 minut
  return access_token;
}

// ════════════════════════════════════════════════════════════════
// GOOGLE SHEETS — CRUD
// ════════════════════════════════════════════════════════════════

async function sheetsRead(env, range) {
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEETS_ID}/values/${encodeURIComponent(range)}`;
  const r = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`Sheets read ${r.status}: ${await r.text()}`);
  return (await r.json()).values || [];
}

async function sheetsAppend(env, sheet, row) {
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEETS_ID}/values/${encodeURIComponent(sheet)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [row] }),
  });
  if (!r.ok) throw new Error(`Sheets append ${r.status}: ${await r.text()}`);
  return r.json();
}

async function sheetsUpdateRow(env, sheet, rowNum, row) {
  const token = await getAccessToken(env);
  // Automaticky určit poslední sloupec podle délky dat
  const lastCol = String.fromCharCode(64 + row.length); // 1→A, 2→B, …
  const range = `${sheet}!A${rowNum}:${lastCol}${rowNum}`;
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEETS_ID}/values/${encodeURIComponent(range)}?valueInputOption=RAW`;
  const r = await fetch(url, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: [row] }),
  });
  if (!r.ok) throw new Error(`Sheets update ${r.status}: ${await r.text()}`);
  return r.json();
}

// Převede pole hodnot na objekt podle názvů sloupců
function rowToObj(cols, row) {
  const obj = {};
  cols.forEach((c, i) => { obj[c] = row[i] ?? ''; });
  return obj;
}

// Načte celý sheet jako pole objektů (přeskočí header řádek)
async function readSheet(env, sheet, cols) {
  const lastCol = String.fromCharCode(64 + cols.length);
  const rows = await sheetsRead(env, `${sheet}!A:${lastCol}`);
  if (rows.length <= 1) return [];
  return rows.slice(1).map(r => rowToObj(cols, r));
}

// Najde číslo řádku v sheetu podle ID (vrátí 1-based index nebo -1)
async function findRowNum(env, sheet, id) {
  const rows = await sheetsRead(env, `${sheet}!A:A`);
  for (let i = 1; i < rows.length; i++) {
    if ((rows[i][0] ?? '') === String(id)) return i + 1; // +1 kvůli header řádku
  }
  return -1;
}

// Generátor unikátních ID
function genId() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

// ════════════════════════════════════════════════════════════════
// VALIDACE VSTUPU
// ════════════════════════════════════════════════════════════════

function validateJmeno(v) {
  if (!v || typeof v !== 'string' || !v.trim()) return 'Jméno je povinné.';
  if (v.trim().length < 2) return 'Jméno musí mít alespoň 2 znaky.';
  if (/^\d+$/.test(v.trim())) return 'Jméno nesmí být jen číslice.';
  return null;
}

function validateEmail(v) {
  if (!v || typeof v !== 'string' || !v.trim()) return 'E-mail je povinný.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim())) return 'E-mail není ve správném formátu.';
  return null;
}

function normTelefon(v) {
  // Odstraní mezery, pomlčky, závorky, tečky
  return v.replace(/[\s\-\(\)\.]/g, '');
}

function validateTelefon(v) {
  if (!v || typeof v !== 'string' || !v.trim()) return 'Telefon je povinný.';
  // Klíčová validace: odmítne písmena (tím padá "místo telefonu jméno")
  if (/[a-zA-ZáčďéěíňóřšťúůýžÁČĎÉĚÍŇÓŘŠŤÚŮÝŽ]/i.test(v)) return 'Telefon nesmí obsahovat písmena.';
  const n = normTelefon(v);
  if (!/^(\+420|\+421|00420|00421)?[0-9]{9}$/.test(n)) {
    return 'Zadejte české nebo slovenské číslo (+420 nebo 9 číslic bez předvolby).';
  }
  return null;
}

function validatePoznamka(v) {
  if (!v) return null; // volitelné
  if (typeof v !== 'string') return 'Poznámka musí být text.';
  if (v.length > 500) return 'Poznámka nesmí být delší než 500 znaků.';
  return null;
}

function sanitize(s) {
  // Základní sanitace: ořízne whitespace, odstraní < a >
  return String(s || '').trim().replace(/[<>]/g, '');
}

// ════════════════════════════════════════════════════════════════
// AUTENTIZACE — PBKDF2 + HMAC SESSION TOKENY
// ════════════════════════════════════════════════════════════════

/**
 * Hashuje heslo pomocí PBKDF2-SHA256 (100 000 iterací).
 * Výstup: "pbkdf2:<saltHex>:<hashHex>"
 * Tato funkce se používá jen v generate-hash.mjs, ne ve Workeru za běhu.
 */
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, km, 256);
  const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${saltHex}:${hashHex}`;
}

/**
 * Ověří heslo vůči uloženému hashi.
 * Porovnání probíhá v konstantním čase (prevence timing attacks).
 */
async function verifyPassword(password, stored) {
  try {
    const [alg, saltHex, expectedHex] = stored.split(':');
    if (alg !== 'pbkdf2') return false;
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' }, km, 256);
    const hashHex = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
    // Konstantní čas
    if (hashHex.length !== expectedHex.length) return false;
    let diff = 0;
    for (let i = 0; i < hashHex.length; i++) diff |= hashHex.charCodeAt(i) ^ expectedHex.charCodeAt(i);
    return diff === 0;
  } catch { return false; }
}

/** Vytvoří session token: base64(payload) + "." + HMAC-SHA256(payload) */
async function createSession(auditorka, env) {
  const payload = { id: auditorka.id, slug: auditorka.slug, jmeno: auditorka.jmeno, exp: Date.now() + 86_400_000 };
  const pB64 = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(pB64));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${pB64}.${sigHex}`;
}

/** Ověří session token; vrátí payload nebo null */
async function verifySession(token, env) {
  try {
    const dot = token.lastIndexOf('.');
    if (dot < 0) return null;
    const pB64 = token.slice(0, dot);
    const sigHex = token.slice(dot + 1);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const expectedSig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(pB64));
    const expectedHex = Array.from(new Uint8Array(expectedSig)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (sigHex.length !== expectedHex.length) return null;
    let diff = 0;
    for (let i = 0; i < sigHex.length; i++) diff |= sigHex.charCodeAt(i) ^ expectedHex.charCodeAt(i);
    if (diff !== 0) return null;
    const p = JSON.parse(atob(pB64));
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

/** Vytáhne session token z Cookie hlavičky */
function getSessionToken(req) {
  const cookie = req.headers.get('Cookie') || '';
  return cookie.match(/(?:^|;\s*)session=([^;]+)/)?.[1] ?? null;
}

/** Middleware: vrátí payload přihlášeného uživatele nebo null */
async function requireAuth(req, env) {
  const token = getSessionToken(req);
  return token ? verifySession(token, env) : null;
}

/** Vygeneruje CSRF token odvozený ze session tokenu */
async function makeCsrf(sessionToken, env) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.AUTH_SECRET + ':csrf'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(sessionToken));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

/** Ověří CSRF token z X-CSRF-Token hlavičky */
async function verifyCsrf(req, env) {
  const token = getSessionToken(req);
  if (!token) return false;
  const header = req.headers.get('X-CSRF-Token');
  if (!header) return false;
  const expected = await makeCsrf(token, env);
  if (header.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < header.length; i++) diff |= header.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — VEŘEJNÉ ENDPOINTY
// ════════════════════════════════════════════════════════════════

/** GET /api/sloty?auditorka={slug} — vrátí volné sloty pro lektory */
async function handleGetSloty(req, env, hdrs) {
  const slug = new URL(req.url).searchParams.get('auditorka');
  if (!slug) return jsonResp({ chyba: 'Chybí parametr auditorka.' }, 400, hdrs);

  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const aud = auditorky.find(a => a.slug === slug && a.aktivni === 'ano');
  if (!aud) return jsonResp({ chyba: 'Odkaz je neplatný nebo auditorka není aktivní.' }, 404, hdrs);

  const dnes = new Date().toISOString().split('T')[0];
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const volne = sloty
    .filter(s => s.auditorka_id === aud.id && s.stav === STAV_VOLNY && s.datum >= dnes)
    .sort((a, b) => a.datum !== b.datum ? a.datum.localeCompare(b.datum) : a.cas_od.localeCompare(b.cas_od))
    .map(({ id, datum, cas_od, cas_do, typ }) => ({ id, datum, cas_od, cas_do, typ }));
  // Interní poznámka a auditorka_id se lektorovi nezobrazují

  return jsonResp({ auditorka: { jmeno: aud.jmeno }, sloty: volne }, 200, hdrs);
}

/** POST /api/rezervace — vytvoří rezervaci (veřejný endpoint) */
async function handlePostRezervace(req, env, hdrs) {
  let body;
  try { body = await req.json(); }
  catch { return jsonResp({ chyba: 'Neplatný formát požadavku.' }, 400, hdrs); }

  const { slot_id, jmeno, email, telefon, poznamka } = body;

  // Serverová validace — lzez obejít na frontendu
  const chyby = {};
  const e1 = validateJmeno(jmeno);    if (e1) chyby.jmeno    = e1;
  const e2 = validateEmail(email);    if (e2) chyby.email    = e2;
  const e3 = validateTelefon(telefon); if (e3) chyby.telefon = e3;
  const e4 = validatePoznamka(poznamka); if (e4) chyby.poznamka = e4;
  if (!slot_id) chyby.slot = 'ID slotu chybí.';
  if (Object.keys(chyby).length) return jsonResp({ chyba: 'Opravte chyby ve formuláři.', chyby }, 422, hdrs);

  // Ověřit, že slot existuje a je volný
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === String(slot_id));
  if (!slot) return jsonResp({ chyba: 'Termín neexistuje.' }, 404, hdrs);
  if (slot.stav !== STAV_VOLNY) return jsonResp({ chyba: 'Tento termín je již obsazený. Vyberte jiný.' }, 409, hdrs);

  // Označit slot jako obsazený PŘED zápisem rezervace (snižuje riziko dvojrezervace)
  const rowNum = await findRowNum(env, SHEET_SLOTY, slot.id);
  if (rowNum === -1) return jsonResp({ chyba: 'Interní chyba. Zkuste to znovu.' }, 500, hdrs);

  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, [
    slot.id, slot.auditorka_id, slot.datum, slot.cas_od, slot.cas_do,
    slot.typ, STAV_OBSAZENY, slot.poznamka_interni,
  ]);

  // Krátká pauza a ověření (základní ochrana proti race condition)
  await new Promise(r => setTimeout(r, 250));
  const slotypo = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const check = slotypo.find(s => s.id === String(slot_id));
  if (!check || check.stav !== STAV_OBSAZENY) {
    return jsonResp({ chyba: 'Termín byl právě obsazen jiným lektorem. Vyberte jiný.' }, 409, hdrs);
  }

  // Uložit rezervaci
  const id = genId();
  await sheetsAppend(env, SHEET_REZERVACE, [
    id,
    slot.id,
    slot.auditorka_id,
    sanitize(jmeno),
    sanitize(email).toLowerCase(),
    normTelefon(sanitize(telefon)),
    sanitize(poznamka || ''),
    new Date().toISOString(),
    REZ_POTVRZENO,
  ]);

  return jsonResp({
    ok: true,
    zprava: `Termín ${slot.datum} ${slot.cas_od}–${slot.cas_do} byl úspěšně rezervován.`,
    id,
  }, 201, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ADMIN PŘIHLÁŠENÍ
// ════════════════════════════════════════════════════════════════

/** POST /api/admin/login */
async function handleLogin(req, env, hdrs) {
  let body;
  try { body = await req.json(); }
  catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }

  const { slug, heslo } = body;
  if (!slug || !heslo) return jsonResp({ chyba: 'Přihlašovací údaje chybí.' }, 400, hdrs);

  // Najít auditorku v Sheets
  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const aud = auditorky.find(a => a.slug === String(slug).trim() && a.aktivni === 'ano');

  // Záměrná pauza zpomaluje brute-force útoky
  if (!aud) {
    await new Promise(r => setTimeout(r, 1000));
    return jsonResp({ chyba: 'Nesprávné přihlašovací údaje.' }, 401, hdrs);
  }

  let passwords;
  try { passwords = JSON.parse(env.AUDITORKA_PASSWORDS || '{}'); }
  catch { return jsonResp({ chyba: 'Chyba konfigurace serveru.' }, 500, hdrs); }

  const stored = passwords[aud.id];
  if (!stored || !(await verifyPassword(heslo, stored))) {
    await new Promise(r => setTimeout(r, 1000));
    return jsonResp({ chyba: 'Nesprávné přihlašovací údaje.' }, 401, hdrs);
  }

  const token = await createSession(aud, env);
  const csrf  = await makeCsrf(token, env);
  const cookie = `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`;

  return jsonResp({ ok: true, jmeno: aud.jmeno, csrfToken: csrf }, 200, { ...hdrs, 'Set-Cookie': cookie });
}

/** POST /api/admin/logout */
function handleLogout(hdrs) {
  return jsonResp({ ok: true }, 200, { ...hdrs, 'Set-Cookie': 'session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' });
}

/** GET /api/admin/me — ověří session, vrátí info + nový CSRF token */
async function handleMe(req, env, hdrs) {
  const aud = await requireAuth(req, env);
  if (!aud) return jsonResp({ chyba: 'Nepřihlášen.' }, 401, hdrs);
  const csrf = await makeCsrf(getSessionToken(req), env);
  return jsonResp({ ok: true, jmeno: aud.jmeno, slug: aud.slug, csrfToken: csrf }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ADMIN SLOTY
// ════════════════════════════════════════════════════════════════

/** GET /api/admin/sloty */
async function handleAdminGetSloty(env, aud, hdrs) {
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  return jsonResp({ sloty: sloty.filter(s => s.auditorka_id === aud.id) }, 200, hdrs);
}

/** POST /api/admin/sloty */
async function handleAdminCreateSlot(req, env, aud, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { datum, cas_od, cas_do, typ, poznamka_interni } = b;
  if (!datum || !cas_od || !cas_do || !typ) return jsonResp({ chyba: 'Datum, čas od, čas do a typ jsou povinné.' }, 422, hdrs);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(datum)) return jsonResp({ chyba: 'Neplatný formát data.' }, 422, hdrs);
  if (!/^\d{2}:\d{2}$/.test(cas_od) || !/^\d{2}:\d{2}$/.test(cas_do)) return jsonResp({ chyba: 'Neplatný formát času.' }, 422, hdrs);
  const id = genId();
  await sheetsAppend(env, SHEET_SLOTY, [id, aud.id, datum, cas_od, cas_do, sanitize(typ), STAV_VOLNY, sanitize(poznamka_interni || '')]);
  return jsonResp({ ok: true, id }, 201, hdrs);
}

/** PUT /api/admin/sloty/:id */
async function handleAdminUpdateSlot(req, env, aud, slotId, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === slotId && s.auditorka_id === aud.id);
  if (!slot) return jsonResp({ chyba: 'Slot nenalezen.' }, 404, hdrs);
  const rowNum = await findRowNum(env, SHEET_SLOTY, slotId);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, [
    slot.id, slot.auditorka_id,
    b.datum ?? slot.datum,
    b.cas_od ?? slot.cas_od,
    b.cas_do ?? slot.cas_do,
    sanitize(b.typ ?? slot.typ),
    b.stav ?? slot.stav,
    sanitize(b.poznamka_interni ?? slot.poznamka_interni),
  ]);
  return jsonResp({ ok: true }, 200, hdrs);
}

/** DELETE /api/admin/sloty/:id (označí jako zrušený, nesmaže fyzicky) */
async function handleAdminDeleteSlot(env, aud, slotId, hdrs) {
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === slotId && s.auditorka_id === aud.id);
  if (!slot) return jsonResp({ chyba: 'Slot nenalezen.' }, 404, hdrs);
  if (slot.stav === STAV_OBSAZENY) return jsonResp({ chyba: 'Nelze smazat obsazený slot. Nejdřív zrušte rezervaci.' }, 409, hdrs);
  const rowNum = await findRowNum(env, SHEET_SLOTY, slotId);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, [
    slot.id, slot.auditorka_id, slot.datum, slot.cas_od, slot.cas_do, slot.typ, STAV_ZRUSEN, slot.poznamka_interni,
  ]);
  return jsonResp({ ok: true }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ADMIN REZERVACE
// ════════════════════════════════════════════════════════════════

/** GET /api/admin/rezervace */
async function handleAdminGetRezervace(env, aud, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const moje = rezervace
    .filter(r => r.auditorka_id === aud.id)
    .sort((a, b) => b.vytvoreno.localeCompare(a.vytvoreno));
  return jsonResp({ rezervace: moje }, 200, hdrs);
}

/** PUT /api/admin/rezervace/:id/zrusit */
async function handleAdminZrushRezervaci(env, aud, rezId, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);
  if (rez.stav === REZ_ZRUSENO) return jsonResp({ chyba: 'Rezervace je již zrušená.' }, 409, hdrs);

  // Zrušit rezervaci
  const rezRow = await findRowNum(env, SHEET_REZERVACE, rezId);
  if (rezRow < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_REZERVACE, rezRow, [
    rez.id, rez.slot_id, rez.auditorka_id, rez.jmeno, rez.email, rez.telefon, rez.poznamka, rez.vytvoreno, REZ_ZRUSENO,
  ]);

  // Uvolnit slot
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === rez.slot_id);
  if (slot) {
    const slotRow = await findRowNum(env, SHEET_SLOTY, slot.id);
    if (slotRow > 0) {
      await sheetsUpdateRow(env, SHEET_SLOTY, slotRow, [
        slot.id, slot.auditorka_id, slot.datum, slot.cas_od, slot.cas_do, slot.typ, STAV_VOLNY, slot.poznamka_interni,
      ]);
    }
  }

  return jsonResp({ ok: true }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — VÝKAZY A EXPORT
// ════════════════════════════════════════════════════════════════

/** GET /api/admin/vykazy */
async function handleAdminVykazy(env, aud, hdrs) {
  const sloty     = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);

  const mojeSloty = sloty.filter(s => s.auditorka_id === aud.id && s.stav !== STAV_ZRUSEN);
  const mojeRez   = rezervace.filter(r => r.auditorka_id === aud.id && r.stav === REZ_POTVRZENO);

  const typy   = {};
  const mesice = {};

  for (const s of mojeSloty) {
    const [hOd, mOd] = s.cas_od.split(':').map(Number);
    const [hDo, mDo] = s.cas_do.split(':').map(Number);
    const h = (hDo * 60 + mDo - hOd * 60 - mOd) / 60;

    typy[s.typ] = (typy[s.typ] || 0) + h;
    const mk = s.datum.slice(0, 7);
    mesice[mk] = (mesice[mk] || 0) + h;
  }

  const round1 = v => Math.round(v * 10) / 10;

  return jsonResp({
    celkem: {
      slotu:      mojeSloty.length,
      obsazenych: mojeSloty.filter(s => s.stav === STAV_OBSAZENY).length,
      rezervaci:  mojeRez.length,
    },
    podle_typu: Object.fromEntries(Object.entries(typy).map(([t, h]) => [t, round1(h)])),
    mesicni: Object.entries(mesice)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([mesic, hodiny]) => ({ mesic, hodiny: round1(hodiny) })),
  }, 200, hdrs);
}

/** GET /api/admin/export — stáhne CSV rezervací */
async function handleAdminExport(env, aud, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const sloty     = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slotyMap  = Object.fromEntries(sloty.map(s => [s.id, s]));

  const esc = v => `"${String(v || '').replace(/"/g, '""')}"`;

  const radky = [
    'ID,Datum,Čas od,Čas do,Typ,Jméno,E-mail,Telefon,Poznámka,Vytvořeno,Stav',
    ...rezervace
      .filter(r => r.auditorka_id === aud.id)
      .map(r => {
        const s = slotyMap[r.slot_id] || {};
        return [r.id, s.datum||'', s.cas_od||'', s.cas_do||'', esc(s.typ), esc(r.jmeno), r.email, r.telefon, esc(r.poznamka), r.vytvoreno, r.stav].join(',');
      }),
  ];

  return new Response(radky.join('\r\n'), {
    status: 200,
    headers: {
      ...hdrs,
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="rezervace-${new Date().toISOString().slice(0,10)}.csv"`,
    },
  });
}

// ════════════════════════════════════════════════════════════════
// HLAVNÍ HANDLER
// ════════════════════════════════════════════════════════════════

export default {
  async fetch(req, env) {
    const url    = new URL(req.url);
    const method = req.method;
    const path   = url.pathname;
    const hdrs   = secHeaders(env.ALLOWED_ORIGIN || '');

    // CORS preflight
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: hdrs });

    // IP pro rate limiting
    const ip = req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For') || 'unknown';

    // Občasné čištění rate limit mapy (1 % šance)
    if (Math.random() < 0.01) cleanRateLimitMap();

    try {

      // ── Veřejné endpointy ──────────────────────────────────

      if (method === 'GET' && path === '/api/sloty') {
        return handleGetSloty(req, env, hdrs);
      }

      if (method === 'POST' && path === '/api/rezervace') {
        if (!checkRateLimit(ip, 'rezervace', 5, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return handlePostRezervace(req, env, hdrs);
      }

      // ── Admin přihlášení ───────────────────────────────────

      if (method === 'POST' && path === '/api/admin/login') {
        if (!checkRateLimit(ip, 'login', 10, 300_000)) {
          return jsonResp({ chyba: 'Příliš mnoho pokusů o přihlášení. Zkuste to za 5 minut.' }, 429, hdrs);
        }
        return handleLogin(req, env, hdrs);
      }

      if (method === 'POST' && path === '/api/admin/logout') {
        return handleLogout(hdrs);
      }

      if (method === 'GET' && path === '/api/admin/me') {
        return handleMe(req, env, hdrs);
      }

      // ── Chráněné admin endpointy ───────────────────────────

      // Všechny /api/admin/* cesty (kromě výše) vyžadují session
      if (!path.startsWith('/api/admin/')) {
        return jsonResp({ chyba: 'Endpoint nenalezen.' }, 404, hdrs);
      }

      const aud = await requireAuth(req, env);
      if (!aud) return jsonResp({ chyba: 'Přihlášení vyžadováno.' }, 401, hdrs);

      // CSRF ochrana na mutace
      if (['POST','PUT','DELETE','PATCH'].includes(method)) {
        if (!(await verifyCsrf(req, env))) {
          return jsonResp({ chyba: 'Neplatný bezpečnostní token. Obnovte stránku a zkuste znovu.' }, 403, hdrs);
        }
      }

      // Sloty
      if (path === '/api/admin/sloty') {
        if (method === 'GET')  return handleAdminGetSloty(env, aud, hdrs);
        if (method === 'POST') return handleAdminCreateSlot(req, env, aud, hdrs);
      }

      const mSlot = path.match(/^\/api\/admin\/sloty\/([^/]+)$/);
      if (mSlot) {
        if (method === 'PUT')    return handleAdminUpdateSlot(req, env, aud, mSlot[1], hdrs);
        if (method === 'DELETE') return handleAdminDeleteSlot(env, aud, mSlot[1], hdrs);
      }

      // Rezervace
      if (path === '/api/admin/rezervace' && method === 'GET') {
        return handleAdminGetRezervace(env, aud, hdrs);
      }

      const mZrush = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/zrusit$/);
      if (mZrush && method === 'PUT') {
        return handleAdminZrushRezervaci(env, aud, mZrush[1], hdrs);
      }

      // Výkazy a export
      if (path === '/api/admin/vykazy' && method === 'GET') return handleAdminVykazy(env, aud, hdrs);
      if (path === '/api/admin/export'  && method === 'GET') return handleAdminExport(env, aud, hdrs);

      return jsonResp({ chyba: 'Endpoint nenalezen.' }, 404, hdrs);

    } catch (err) {
      // V produkci nesmí unikat detaily chyb
      return jsonResp({ chyba: 'Interní chyba serveru.' }, 500, hdrs);
    }
  },
};
