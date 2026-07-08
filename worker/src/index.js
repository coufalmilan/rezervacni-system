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
 *   BREVO_API_KEY         – API klíč z Brevo (https://app.brevo.com → SMTP & API → API Keys),
 *                            slouží k odeslání potvrzovacích e-mailů (+ .ics). Odesílací adresa
 *                            (e-mail auditorky z listu Auditorky) musí být v Brevo předem ověřená
 *                            jako "Sender" (Contacts → Senders → Add a sender). Viz SETUP.md krok 4.
 */

// ════════════════════════════════════════════════════════════════
// KONSTANTY
// ════════════════════════════════════════════════════════════════

const SHEET_AUDITORKY     = 'Auditorky';
const SHEET_SLOTY         = 'Sloty';
const SHEET_REZERVACE     = 'Rezervace';
const SHEET_ADMINISTRATIVA = 'Administrativa';

// Sloupce jednotlivých listů (POŘADÍ musí přesně odpovídat sloupcům v Google Sheets!)
const COLS_AUDITORKY = ['id', 'jmeno', 'slug', 'email', 'teams_odkaz', 'jazyk', 'sazba_60min', 'aktivni'];
const COLS_SLOTY     = ['id', 'auditorka_id', 'datum', 'cas_od', 'cas_do', 'stav', 'poznamka_interni'];
const COLS_REZERVACE = [
  'id', 'slot_id', 'auditorka_id', 'jmeno', 'email', 'kontakt_zpusob', 'telefon',
  'poznamka', 'vytvoreno', 'firma', 'typ_cinnosti', 'stav', 'teams_odkaz',
  'vysledek', 'kurz', 'ostatni_kompetence_ok', 'cas_pro_mzdu_min',
  // Přidáno ve Fázi 5 (rozšíření) — připojeno na KONEC seznamu sloupců schválně,
  // aby stávající tabulky se 17 sloupci nebylo potřeba přeskládávat (staré řádky
  // budou mít token/zdroj jen prázdné, dokud se nedoplní nový sloupec v Sheets).
  'token', 'zdroj',
];
const COLS_ADMINISTRATIVA = ['id', 'auditorka_id', 'datum', 'vysledek_poznamka', 'cas_pro_mzdu_min', 'firma'];

// Stavy slotu
const STAV_VOLNY    = 'volny';
const STAV_OBSAZENY = 'obsazeny';
const STAV_ZRUSEN   = 'zrusen';

// Stavy rezervace
const REZ_REZERVOVANO  = 'rezervovano';
const REZ_USKUTECNENO  = 'uskutecneno';
const REZ_ZRUSENO      = 'zruseno';
const REZ_NEDOSTAVIL   = 'nedostavil_se'; // Fáze 5, funkce 2 — no-show

// Zdroj rezervace (Fáze 5, funkce 3)
const ZDROJ_WEB   = 'web';
const ZDROJ_RUCNE = 'rucne';

// Způsob kontaktu, který si lektor vybírá
const KONTAKT_TELEFON = 'telefon';
const KONTAKT_TEAMS   = 'teams';

// Typ činnosti — přiřazuje auditorka až u rezervace (ne u slotu)
const TYP_VSTUPNI  = 'Vstupní audit';
const TYP_KONTROLA = 'Kontrola hodnocení';

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
    'Access-Control-Allow-Headers': 'Content-Type, X-CSRF-Token, Authorization',
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
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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

/** Hromadný append více řádků najednou — jeden API call pro všechny */
async function sheetsAppendBulk(env, sheet, rows) {
  if (!rows.length) return;
  const token = await getAccessToken(env);
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${env.SHEETS_ID}/values/${encodeURIComponent(sheet)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ values: rows }),
  });
  if (!r.ok) throw new Error(`Sheets bulk append ${r.status}: ${await r.text()}`);
  return r.json();
}

async function sheetsUpdateRow(env, sheet, rowNum, row) {
  const token = await getAccessToken(env);
  // Automaticky určit poslední sloupec podle délky dat (podporuje i sloupce za Z, např. AA)
  const lastCol = colLetter(row.length);
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

// Převede číslo sloupce (1-based) na písmeno/písmena Google Sheets sloupce (1→A, 27→AA…)
function colLetter(n) {
  let s = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    s = String.fromCharCode(65 + rem) + s;
    n = Math.floor((n - 1) / 26);
  }
  return s;
}

// Převede pole hodnot na objekt podle názvů sloupců
function rowToObj(cols, row) {
  const obj = {};
  cols.forEach((c, i) => { obj[c] = row[i] ?? ''; });
  return obj;
}

// Převede objekt zpět na pole hodnot ve správném pořadí sloupců (opak rowToObj)
// Díky tomu při ukládání řádku stačí upravit jen konkrétní pole objektu,
// aniž bychom museli ručně vypisovat všech 17 sloupců pokaždé znovu.
function objToRow(cols, obj) {
  return cols.map(c => obj[c] ?? '');
}

// Načte celý sheet jako pole objektů (přeskočí header řádek)
async function readSheet(env, sheet, cols) {
  const lastCol = colLetter(cols.length);
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

// Generátor bezpečného tokenu pro samoobslužný odkaz (Fáze 5, funkce 1).
// Na rozdíl od genId() používá kryptograficky náhodná čísla (crypto.getRandomValues),
// aby token nešel uhodnout ani odvodit — 24 bajtů (192 bitů) je dostatečně dlouhé.
function genToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
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

function validateKontaktZpusob(v) {
  if (v !== KONTAKT_TELEFON && v !== KONTAKT_TEAMS) return 'Vyberte způsob kontaktu (telefon, nebo schůzka přes MS Teams).';
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

function validateCasProMzdu(v) {
  const cas = parseInt(v, 10);
  if (!Number.isFinite(cas) || cas <= 0 || cas % 15 !== 0) {
    return 'Čas pro mzdu musí být kladné číslo, zadané po 15 minutách (15, 30, 45…).';
  }
  return null;
}

function sanitize(s) {
  // Základní sanitace: ořízne whitespace, odstraní < a >
  return String(s || '').trim().replace(/[<>]/g, '');
}

function escHtml(s) {
  // Escapování pro vložení do HTML e-mailu (na rozdíl od sanitize() nic neodstraňuje, jen escapuje)
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ════════════════════════════════════════════════════════════════
// AUTENTIZACE — PBKDF2 + HMAC SESSION TOKENY
// ════════════════════════════════════════════════════════════════

// ── KV helpers pro hesla ────────────────────────────────────────────────────
// Heslo se hledá nejdřív v KV (PASSWORDS_KV), pak fallback na AUDITORKA_PASSWORDS secret.
// Po první změně hesla přes admin UI je heslo vždy v KV.

async function getStoredPassword(env, auditorkaId) {
  if (env.PASSWORDS_KV) {
    const kv = await env.PASSWORDS_KV.get(`pwd:${auditorkaId}`);
    if (kv) return kv;
  }
  // Fallback: původní secret (pro první přihlášení před změnou hesla)
  try {
    const passwords = JSON.parse(env.AUDITORKA_PASSWORDS || '{}');
    return passwords[String(auditorkaId)] || null;
  } catch { return null; }
}

async function setStoredPassword(env, auditorkaId, hash) {
  await env.PASSWORDS_KV.put(`pwd:${auditorkaId}`, hash);
}

// ─────────────────────────────────────────────────────────────────────────────

/**
 * Hashuje heslo pomocí PBKDF2-SHA256 (100 000 iterací).
 * Výstup: "pbkdf2:<saltHex>:<hashHex>"
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

/** Vytáhne session token — nejdřív z Authorization: Bearer hlavičky, pak z Cookie */
function getSessionToken(req) {
  // Preferujeme Bearer token — funguje cross-domain bez omezení cookie politik
  const auth = req.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ')) {
    const t = auth.slice(7).trim();
    if (t) return t;
  }
  // Fallback na cookie (stejná doména nebo starší prohlížeče)
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
// E-MAIL A KALENDÁŘOVÁ POZVÁNKA (.ics) — přes Brevo (transakční e-mailová služba)
// ════════════════════════════════════════════════════════════════

// Zakóduje text (i s českou diakritikou) do Base64 — obyčejné btoa() na to nestačí,
// protože umí jen jednobajtové znaky. Používá se pro .ics přílohu v Brevo API.
function utf8ToBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  bytes.forEach(b => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

// Jednoduché formátování data "2026-07-02" → "2.7.2026" (bez závislosti na locale enginu)
function formatDatumCz(iso) {
  const [y, m, d] = String(iso).split('-');
  return `${parseInt(d, 10)}.${parseInt(m, 10)}.${y}`;
}

// Escapování textu pro .ics soubor (podle RFC 5545)
function icsEscape(s) {
  return String(s || '')
    .replace(/\\/g, '\\\\')
    .replace(/;/g, '\\;')
    .replace(/,/g, '\\,')
    .replace(/\n/g, '\\n');
}

// Datum+čas ve formátu .ics (např. "20260702T090000"). Používáme "plovoucí" čas
// (bez Z a bez TZID/VTIMEZONE bloku) — kalendářová aplikace ho zobrazí v místním
// čase prohlížejícího. Zjednodušení, které funguje pro obě strany v ČR/SR.
function toIcsDateTime(datum, cas) {
  const [h, m] = cas.split(':');
  return `${datum.replace(/-/g, '')}T${h}${m}00`;
}

/** Sestaví obsah .ics souboru (kalendářová pozvánka) pro jednu schůzku */
function buildIcs({ uid, datum, casOd, casDo, summary, description, location, organizerEmail, organizerName, attendeeEmail, attendeeName }) {
  const dtStamp = new Date().toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
  const lines = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//Rezervacni system//CZ',
    'CALSCALE:GREGORIAN',
    'METHOD:REQUEST',
    'BEGIN:VEVENT',
    `UID:${uid}`,
    `DTSTAMP:${dtStamp}`,
    `DTSTART:${toIcsDateTime(datum, casOd)}`,
    `DTEND:${toIcsDateTime(datum, casDo)}`,
    `SUMMARY:${icsEscape(summary)}`,
    `DESCRIPTION:${icsEscape(description)}`,
    location ? `LOCATION:${icsEscape(location)}` : null,
    `ORGANIZER;CN=${icsEscape(organizerName)}:mailto:${organizerEmail}`,
    `ATTENDEE;CN=${icsEscape(attendeeName)};ROLE=REQ-PARTICIPANT;RSVP=TRUE:mailto:${attendeeEmail}`,
    'STATUS:CONFIRMED',
    'SEQUENCE:0',
    'BEGIN:VALARM',
    'ACTION:DISPLAY',
    'DESCRIPTION:Připomínka schůzky',
    'TRIGGER:-PT15M',
    'END:VALARM',
    'END:VEVENT',
    'END:VCALENDAR',
  ];
  return lines.filter(Boolean).join('\r\n');
}

/**
 * Odešle e-mail (volitelně s .ics přílohou) přes Brevo (https://www.brevo.com).
 * Odesílací adresa (fromEmail) musí být v Brevo předem ověřená jako "Sender"
 * (Contacts → Senders → Add a sender) — jinak Brevo odeslání odmítne.
 * API klíč se čte ze secretu BREVO_API_KEY (Cloudflare).
 */
async function sendEmail(env, { to, cc, fromEmail, fromName, subject, html, icsContent, icsFilename }) {
  if (!env.BREVO_API_KEY) {
    throw new Error('E-mailová služba není nastavená (chybí secret BREVO_API_KEY). Viz SETUP.md.');
  }
  if (!fromEmail) {
    throw new Error('Chybí odesílací adresa (fromEmail) — nelze odeslat e-mail.');
  }

  const toList = (Array.isArray(to) ? to : [to]).map(e => ({ email: e }));

  const payload = {
    sender: fromName ? { email: fromEmail, name: fromName } : { email: fromEmail },
    to: toList,
    subject,
    htmlContent: html,
  };
  if (cc) {
    payload.cc = (Array.isArray(cc) ? cc : [cc]).map(e => ({ email: e }));
  }
  if (icsContent) {
    payload.attachment = [{
      content: utf8ToBase64(icsContent),
      name: icsFilename || 'schuzka.ics',
    }];
  }

  const r = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': env.BREVO_API_KEY,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(`Brevo chyba ${r.status}: ${data.message || JSON.stringify(data)}`);
  }
  return data;
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
    .map(({ id, datum, cas_od, cas_do }) => ({ id, datum, cas_od, cas_do }));
  // Interní poznámka, stav auditorka_id a typ činnosti se lektorovi nezobrazují
  // (typ činnosti se u slotu vůbec nezadává — přiřazuje ho auditorka až u rezervace)

  return jsonResp({ auditorka: { jmeno: aud.jmeno }, sloty: volne }, 200, hdrs);
}

/** POST /api/rezervace — vytvoří rezervaci (veřejný endpoint) */
async function handlePostRezervace(req, env, hdrs, ctx) {
  let body;
  try { body = await req.json(); }
  catch { return jsonResp({ chyba: 'Neplatný formát požadavku.' }, 400, hdrs); }

  const { slot_id, jmeno, email, kontakt_zpusob, telefon, poznamka, stranka } = body;

  // Honeypot proti botům (Fáze 5, funkce 8): pole "stranka" je ve formuláři skryté
  // přes CSS, takže ho vyplní jen automatizovaný skript, ne člověk. Když je vyplněné,
  // tváříme se navenek, že rezervace proběhla úspěšně (aby bot nezjistil, že byl odhalen),
  // ale nic se ve skutečnosti neuloží ani neobsadí.
  if (stranka) {
    return jsonResp({ ok: true, zprava: 'Rezervace byla přijata.', id: genId() }, 201, hdrs);
  }

  // Serverová validace — lze obejít na frontendu, proto musí běžet i tady
  const chyby = {};
  const e1 = validateJmeno(jmeno);                 if (e1) chyby.jmeno = e1;
  const e2 = validateEmail(email);                 if (e2) chyby.email = e2;
  const e3 = validateKontaktZpusob(kontakt_zpusob); if (e3) chyby.kontakt_zpusob = e3;
  // Telefon je povinný jen když si lektor zvolil kontakt "telefon"
  if (kontakt_zpusob === KONTAKT_TELEFON) {
    const e4 = validateTelefon(telefon);
    if (e4) chyby.telefon = e4;
  }
  const e5 = validatePoznamka(poznamka); if (e5) chyby.poznamka = e5;
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

  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, objToRow(COLS_SLOTY, { ...slot, stav: STAV_OBSAZENY }));

  // Krátká pauza a ověření (základní ochrana proti race condition)
  await new Promise(r => setTimeout(r, 250));
  const slotypo = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const check = slotypo.find(s => s.id === String(slot_id));
  if (!check || check.stav !== STAV_OBSAZENY) {
    return jsonResp({ chyba: 'Termín byl právě obsazen jiným lektorem. Vyberte jiný.' }, 409, hdrs);
  }

  // Uložit rezervaci — typ_cinnosti, firma, výsledek atd. se doplní až v adminu
  const id = genId();
  const telefonNorm = kontakt_zpusob === KONTAKT_TELEFON ? normTelefon(sanitize(telefon)) : '';

  const novaRezervace = {
    id,
    slot_id: slot.id,
    auditorka_id: slot.auditorka_id,
    jmeno: sanitize(jmeno),
    email: sanitize(email).toLowerCase(),
    kontakt_zpusob,
    telefon: telefonNorm,
    poznamka: sanitize(poznamka || ''),
    vytvoreno: new Date().toISOString(),
    firma: '',
    typ_cinnosti: '',
    stav: REZ_REZERVOVANO,
    teams_odkaz: '',
    vysledek: '',
    kurz: '',
    ostatni_kompetence_ok: '',
    cas_pro_mzdu_min: '',
    token: genToken(),
    zdroj: ZDROJ_WEB,
  };
  await sheetsAppend(env, SHEET_REZERVACE, objToRow(COLS_REZERVACE, novaRezervace));

  // Potvrzovací e-mail + .ics pozvánka se posílají automaticky, na pozadí (§8 zadání
  // to jako alternativu k tlačítku výslovně dovoluje). ctx.waitUntil zajistí, že Worker
  // počká s odesláním, ale lektor na to nečeká — dostane odpověď hned. Případná chyba
  // e-mailové brány (např. výpadek Brevo) se jen zaloguje a rezervaci nijak nezruší.
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(
      posliPotvrzeni(env, novaRezervace, slot).catch(err => {
        console.error('Automatické odeslání potvrzení selhalo:', err?.message || err);
      })
    );
  }

  return jsonResp({
    ok: true,
    zprava: `Termín ${slot.datum} ${slot.cas_od}–${slot.cas_do} byl úspěšně rezervován. Na e-mail vám brzy dorazí potvrzení s pozvánkou do kalendáře.`,
    id,
  }, 201, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — SAMOOBSLUHA LEKTORA PŘES TOKEN (Fáze 5, funkce 1)
// Bez přihlášení — lektor přistupuje přes jednorázový token z potvrzovacího e-mailu.
// ════════════════════════════════════════════════════════════════

/** GET /api/rezervace/{token} — detail rezervace pro samoobslužnou stránku */
async function handleGetRezervaceToken(env, token, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.token && r.token === token);
  if (!rez) return jsonResp({ chyba: 'Odkaz je neplatný nebo rezervace už neexistuje.' }, 404, hdrs);

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === rez.slot_id);
  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const aud = auditorky.find(a => a.id === rez.auditorka_id);

  return jsonResp({
    rezervace: {
      jmeno: rez.jmeno,
      email: rez.email,
      kontakt_zpusob: rez.kontakt_zpusob,
      telefon: rez.telefon,
      stav: rez.stav,
      datum: slot?.datum || '',
      cas_od: slot?.cas_od || '',
      cas_do: slot?.cas_do || '',
      auditorka: aud?.jmeno || '',
    },
  }, 200, hdrs);
}

/** GET /api/rezervace/{token}/sloty — volné termíny stejné auditorky (pro přesun) */
async function handleGetVolneSlotyToken(env, token, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.token && r.token === token);
  if (!rez) return jsonResp({ chyba: 'Odkaz je neplatný.' }, 404, hdrs);

  const dnes = new Date().toISOString().split('T')[0];
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const volne = sloty
    .filter(s => s.auditorka_id === rez.auditorka_id && s.stav === STAV_VOLNY && s.datum >= dnes)
    .sort((a, b) => a.datum !== b.datum ? a.datum.localeCompare(b.datum) : a.cas_od.localeCompare(b.cas_od))
    .map(({ id, datum, cas_od, cas_do }) => ({ id, datum, cas_od, cas_do }));

  return jsonResp({ sloty: volne }, 200, hdrs);
}

/** POST /api/rezervace/{token}/zrusit — samoobslužné zrušení termínu */
async function handleTokenZrusit(env, token, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.token && r.token === token);
  if (!rez) return jsonResp({ chyba: 'Odkaz je neplatný.' }, 404, hdrs);
  if (rez.stav !== REZ_REZERVOVANO) return jsonResp({ chyba: 'Tuto rezervaci už nelze zrušit — není aktivní.' }, 409, hdrs);

  const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba. Zkuste to znovu.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, { ...rez, stav: REZ_ZRUSENO }));

  // Uvolnit slot, ať si ho může rezervovat jiný lektor
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === rez.slot_id);
  if (slot) {
    const slotRow = await findRowNum(env, SHEET_SLOTY, slot.id);
    if (slotRow > 0) await sheetsUpdateRow(env, SHEET_SLOTY, slotRow, objToRow(COLS_SLOTY, { ...slot, stav: STAV_VOLNY }));
  }

  // Upozornit auditorku e-mailem (best-effort — chyba se jen zaloguje, zrušení už proběhlo)
  try {
    const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
    const aud = auditorky.find(a => a.id === rez.auditorka_id);
    if (aud?.email && slot) {
      await sendEmail(env, {
        to: aud.email,
        fromEmail: aud.email,
        fromName: aud.jmeno,
        subject: `Lektor zrušil termín — ${formatDatumCz(slot.datum)} ${slot.cas_od}`,
        html: `<p>Lektor <strong>${escHtml(rez.jmeno)}</strong> (${escHtml(rez.email)}) zrušil termín
          <strong>${formatDatumCz(slot.datum)}, ${slot.cas_od}–${slot.cas_do}</strong>. Slot je opět volný v adminu.</p>`,
      });
    }
  } catch (err) {
    console.error('Upozornění auditorky o zrušení selhalo:', err?.message || err);
  }

  return jsonResp({ ok: true, zprava: 'Termín byl zrušen. Auditorka byla informována.' }, 200, hdrs);
}

/** POST /api/rezervace/{token}/presunout — samoobslužný přesun na jiný volný termín */
async function handleTokenPresunout(req, env, token, hdrs, ctx) {
  let body; try { body = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { novy_slot_id } = body;
  if (!novy_slot_id) return jsonResp({ chyba: 'Vyberte nový termín.' }, 400, hdrs);

  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.token && r.token === token);
  if (!rez) return jsonResp({ chyba: 'Odkaz je neplatný.' }, 404, hdrs);
  if (rez.stav !== REZ_REZERVOVANO) return jsonResp({ chyba: 'Tuto rezervaci už nelze přesunout — není aktivní.' }, 409, hdrs);
  if (String(novy_slot_id) === String(rez.slot_id)) return jsonResp({ chyba: 'Vyberte jiný termín, než máte teď.' }, 422, hdrs);

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const novySlot = sloty.find(s => s.id === String(novy_slot_id));
  if (!novySlot) return jsonResp({ chyba: 'Termín neexistuje.' }, 404, hdrs);
  if (novySlot.auditorka_id !== rez.auditorka_id) return jsonResp({ chyba: 'Termín nepatří ke stejné auditorce.' }, 400, hdrs);
  if (novySlot.stav !== STAV_VOLNY) return jsonResp({ chyba: 'Tento termín je již obsazený. Vyberte jiný.' }, 409, hdrs);

  const staryslot = sloty.find(s => s.id === rez.slot_id);

  // Zamknout nový slot — stejná ochrana proti dvojrezervaci jako u nové rezervace
  const novyRow = await findRowNum(env, SHEET_SLOTY, novySlot.id);
  if (novyRow < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_SLOTY, novyRow, objToRow(COLS_SLOTY, { ...novySlot, stav: STAV_OBSAZENY }));
  await new Promise(r => setTimeout(r, 250));
  const slotyPo = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const check = slotyPo.find(s => s.id === String(novy_slot_id));
  if (!check || check.stav !== STAV_OBSAZENY) {
    return jsonResp({ chyba: 'Termín byl právě obsazen někým jiným. Vyberte jiný.' }, 409, hdrs);
  }

  // Uvolnit starý slot
  if (staryslot) {
    const staryRow = await findRowNum(env, SHEET_SLOTY, staryslot.id);
    if (staryRow > 0) await sheetsUpdateRow(env, SHEET_SLOTY, staryRow, objToRow(COLS_SLOTY, { ...staryslot, stav: STAV_VOLNY }));
  }

  // Přepsat rezervaci na nový slot — token zůstává stejný, odkaz dál funguje
  const rezRow = await findRowNum(env, SHEET_REZERVACE, rez.id);
  const updatedRez = { ...rez, slot_id: novySlot.id };
  if (rezRow > 0) await sheetsUpdateRow(env, SHEET_REZERVACE, rezRow, objToRow(COLS_REZERVACE, updatedRez));

  // Poslat nové potvrzení s aktuálním termínem (na pozadí, chyba se jen zaloguje)
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(
      posliPotvrzeni(env, updatedRez, novySlot).catch(err => {
        console.error('Potvrzení po přesunu selhalo:', err?.message || err);
      })
    );
  }

  return jsonResp({
    ok: true,
    zprava: `Termín byl přesunut na ${formatDatumCz(novySlot.datum)}, ${novySlot.cas_od}–${novySlot.cas_do}. Nové potvrzení vám brzy dorazí e-mailem.`,
  }, 200, hdrs);
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

  const stored = await getStoredPassword(env, aud.id);
  if (!stored || !(await verifyPassword(heslo, stored))) {
    await new Promise(r => setTimeout(r, 1000));
    return jsonResp({ chyba: 'Nesprávné přihlašovací údaje.' }, 401, hdrs);
  }

  const token = await createSession(aud, env);
  const csrf  = await makeCsrf(token, env);
  const cookie = `session=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=86400`;

  // sessionToken v těle odpovědi — frontend ho uloží a posílá jako Authorization: Bearer
  // Tím obcházíme blokování cross-domain cookies v moderních prohlížečích
  // sazba_60min posíláme rovnou i sem, aby admin UI mohlo hned počítat částku k výplatě
  return jsonResp({
    ok: true, jmeno: aud.jmeno, csrfToken: csrf, sessionToken: token,
    sazba_60min: aud.sazba_60min || '',
  }, 200, { ...hdrs, 'Set-Cookie': cookie });
}

/** POST /api/admin/logout */
function handleLogout(hdrs) {
  return jsonResp({ ok: true }, 200, { ...hdrs, 'Set-Cookie': 'session=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0' });
}

/** GET /api/admin/me — ověří session, vrátí info + nový CSRF token */
async function handleMe(req, env, hdrs) {
  const aud = await requireAuth(req, env);
  if (!aud) return jsonResp({ chyba: 'Nepřihlášen.' }, 401, hdrs);
  const rawToken = getSessionToken(req);
  const csrf = await makeCsrf(rawToken, env);

  // Session obsahuje jen id/slug/jméno — sazbu pro výkazy dotáhneme z Sheets
  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const auditorkaFull = auditorky.find(a => a.id === aud.id);

  // Vrátíme i sessionToken, aby si ho frontend mohl uložit i po refreshi stránky
  return jsonResp({
    ok: true, jmeno: aud.jmeno, slug: aud.slug, csrfToken: csrf, sessionToken: rawToken,
    sazba_60min: auditorkaFull?.sazba_60min || '',
  }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ZMĚNA HESLA
// ════════════════════════════════════════════════════════════════

/** POST /api/admin/change-password */
async function handleChangePassword(req, env, aud, hdrs) {
  let body;
  try { body = await req.json(); }
  catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }

  const { heslo_stare, heslo_nove } = body;
  if (!heslo_stare || !heslo_nove) return jsonResp({ chyba: 'Vyplňte obě pole.' }, 400, hdrs);
  if (heslo_nove.length < 8) return jsonResp({ chyba: 'Nové heslo musí mít alespoň 8 znaků.' }, 422, hdrs);
  if (heslo_nove === heslo_stare) return jsonResp({ chyba: 'Nové heslo musí být jiné než staré.' }, 422, hdrs);

  const stored = await getStoredPassword(env, aud.id);
  if (!stored || !(await verifyPassword(heslo_stare, stored))) {
    await new Promise(r => setTimeout(r, 1000));
    return jsonResp({ chyba: 'Staré heslo není správné.' }, 401, hdrs);
  }

  const newHash = await hashPassword(heslo_nove);
  await setStoredPassword(env, aud.id, newHash);

  return jsonResp({ ok: true, zprava: 'Heslo bylo úspěšně změněno.' }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ADMIN SLOTY  (typ činnosti se tu NEZADÁVÁ, viz §5/§10 zadání)
// ════════════════════════════════════════════════════════════════

/** GET /api/admin/sloty */
async function handleAdminGetSloty(env, aud, hdrs) {
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  return jsonResp({ sloty: sloty.filter(s => s.auditorka_id === aud.id) }, 200, hdrs);
}

/** POST /api/admin/sloty */
async function handleAdminCreateSlot(req, env, aud, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { datum, cas_od, cas_do, poznamka_interni } = b;
  if (!datum || !cas_od || !cas_do) return jsonResp({ chyba: 'Datum, čas od a čas do jsou povinné.' }, 422, hdrs);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(datum)) return jsonResp({ chyba: 'Neplatný formát data.' }, 422, hdrs);
  if (!/^\d{2}:\d{2}$/.test(cas_od) || !/^\d{2}:\d{2}$/.test(cas_do)) return jsonResp({ chyba: 'Neplatný formát času.' }, 422, hdrs);
  const id = genId();
  await sheetsAppend(env, SHEET_SLOTY, objToRow(COLS_SLOTY, {
    id, auditorka_id: aud.id, datum, cas_od, cas_do, stav: STAV_VOLNY, poznamka_interni: sanitize(poznamka_interni || ''),
  }));
  return jsonResp({ ok: true, id }, 201, hdrs);
}

/** POST /api/admin/sloty/bulk — hromadné vytvoření slotů */
async function handleAdminCreateSlotsBulk(req, env, aud, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { sloty } = b;
  if (!Array.isArray(sloty) || sloty.length === 0) return jsonResp({ chyba: 'Žádné sloty k vytvoření.' }, 400, hdrs);
  if (sloty.length > 200) return jsonResp({ chyba: 'Maximálně 200 slotů najednou.' }, 422, hdrs);
  for (const s of sloty) {
    if (!s.datum || !s.cas_od || !s.cas_do) return jsonResp({ chyba: 'Každý slot musí mít datum, čas od a čas do.' }, 422, hdrs);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s.datum)) return jsonResp({ chyba: 'Neplatný formát data.' }, 422, hdrs);
    if (!/^\d{2}:\d{2}$/.test(s.cas_od) || !/^\d{2}:\d{2}$/.test(s.cas_do)) return jsonResp({ chyba: 'Neplatný formát času.' }, 422, hdrs);
  }
  const rows = sloty.map(s => objToRow(COLS_SLOTY, {
    id: genId(), auditorka_id: aud.id, datum: s.datum, cas_od: s.cas_od, cas_do: s.cas_do,
    stav: STAV_VOLNY, poznamka_interni: sanitize(s.poznamka_interni || ''),
  }));
  await sheetsAppendBulk(env, SHEET_SLOTY, rows);
  return jsonResp({ ok: true, vytvoreno: rows.length }, 201, hdrs);
}

/** PUT /api/admin/sloty/:id */
async function handleAdminUpdateSlot(req, env, aud, slotId, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === slotId && s.auditorka_id === aud.id);
  if (!slot) return jsonResp({ chyba: 'Slot nenalezen.' }, 404, hdrs);
  const rowNum = await findRowNum(env, SHEET_SLOTY, slotId);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  const updated = {
    ...slot,
    datum: b.datum ?? slot.datum,
    cas_od: b.cas_od ?? slot.cas_od,
    cas_do: b.cas_do ?? slot.cas_do,
    stav: b.stav ?? slot.stav,
    poznamka_interni: b.poznamka_interni !== undefined ? sanitize(b.poznamka_interni) : slot.poznamka_interni,
  };
  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, objToRow(COLS_SLOTY, updated));
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
  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, objToRow(COLS_SLOTY, { ...slot, stav: STAV_ZRUSEN }));
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
  if (rez.stav !== REZ_REZERVOVANO) return jsonResp({ chyba: 'Lze zrušit jen aktivní (dosud nevyřízenou) rezervaci.' }, 409, hdrs);

  // Zrušit rezervaci
  const rezRow = await findRowNum(env, SHEET_REZERVACE, rezId);
  if (rezRow < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_REZERVACE, rezRow, objToRow(COLS_REZERVACE, { ...rez, stav: REZ_ZRUSENO }));

  // Uvolnit slot, aby si ho mohl rezervovat jiný lektor
  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === rez.slot_id);
  if (slot) {
    const slotRow = await findRowNum(env, SHEET_SLOTY, slot.id);
    if (slotRow > 0) {
      await sheetsUpdateRow(env, SHEET_SLOTY, slotRow, objToRow(COLS_SLOTY, { ...slot, stav: STAV_VOLNY }));
    }
  }

  return jsonResp({ ok: true }, 200, hdrs);
}

/** PUT /api/admin/rezervace/:id/nedostavil-se — Fáze 5, funkce 2 (no-show) */
async function handleAdminNedostavilSe(env, aud, rezId, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);
  if (rez.stav !== REZ_REZERVOVANO) return jsonResp({ chyba: 'Lze označit jen aktivní (dosud nevyřízenou) rezervaci.' }, 409, hdrs);

  const rowNum = await findRowNum(env, SHEET_REZERVACE, rezId);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, { ...rez, stav: REZ_NEDOSTAVIL }));
  // Slot záměrně zůstává "obsazený" — termín už proběhl (resp. měl proběhnout), jde jen o evidenci.
  return jsonResp({ ok: true }, 200, hdrs);
}

/** POST /api/admin/rezervace — ruční přidání rezervace auditorkou (Fáze 5, funkce 3) */
async function handleAdminCreateRezervace(req, env, aud, hdrs, ctx) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { slot_id, jmeno, email, kontakt_zpusob, telefon, poznamka } = b;

  // Stejná validace jako u veřejné rezervace (§7 zadání)
  const chyby = {};
  const e1 = validateJmeno(jmeno);                 if (e1) chyby.jmeno = e1;
  const e2 = validateEmail(email);                 if (e2) chyby.email = e2;
  const e3 = validateKontaktZpusob(kontakt_zpusob); if (e3) chyby.kontakt_zpusob = e3;
  if (kontakt_zpusob === KONTAKT_TELEFON) {
    const e4 = validateTelefon(telefon);
    if (e4) chyby.telefon = e4;
  }
  const e5 = validatePoznamka(poznamka); if (e5) chyby.poznamka = e5;
  if (!slot_id) chyby.slot = 'Vyberte termín.';
  if (Object.keys(chyby).length) return jsonResp({ chyba: 'Opravte chyby ve formuláři.', chyby }, 422, hdrs);

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === String(slot_id) && s.auditorka_id === aud.id);
  if (!slot) return jsonResp({ chyba: 'Termín nenalezen.' }, 404, hdrs);
  if (slot.stav !== STAV_VOLNY) return jsonResp({ chyba: 'Tento termín je již obsazený.' }, 409, hdrs);

  const rowNum = await findRowNum(env, SHEET_SLOTY, slot.id);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_SLOTY, rowNum, objToRow(COLS_SLOTY, { ...slot, stav: STAV_OBSAZENY }));

  const id = genId();
  const telefonNorm = kontakt_zpusob === KONTAKT_TELEFON ? normTelefon(sanitize(telefon)) : '';
  const novaRezervace = {
    id, slot_id: slot.id, auditorka_id: aud.id,
    jmeno: sanitize(jmeno), email: sanitize(email).toLowerCase(),
    kontakt_zpusob, telefon: telefonNorm, poznamka: sanitize(poznamka || ''),
    vytvoreno: new Date().toISOString(), firma: '', typ_cinnosti: '', stav: REZ_REZERVOVANO,
    teams_odkaz: '', vysledek: '', kurz: '', ostatni_kompetence_ok: '', cas_pro_mzdu_min: '',
    token: genToken(), zdroj: ZDROJ_RUCNE,
  };
  await sheetsAppend(env, SHEET_REZERVACE, objToRow(COLS_REZERVACE, novaRezervace));

  // Stejně jako u webové rezervace pošleme potvrzení automaticky na pozadí
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(
      posliPotvrzeni(env, novaRezervace, slot).catch(err => {
        console.error('Automatické odeslání potvrzení (ruční přidání) selhalo:', err?.message || err);
      })
    );
  }

  return jsonResp({ ok: true, id }, 201, hdrs);
}

/** GET /api/admin/prehled — denní/týdenní agenda na úvod (Fáze 5, funkce 4) */
async function handleAdminPrehled(env, aud, hdrs) {
  const dnes = new Date().toISOString().split('T')[0];
  const zaTydenDate = new Date();
  zaTydenDate.setDate(zaTydenDate.getDate() + 7);
  const zaTyden = zaTydenDate.toISOString().split('T')[0];

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slotyMap = Object.fromEntries(sloty.map(s => [s.id, s]));
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);

  const aktivni = rezervace
    .filter(r => r.auditorka_id === aud.id && r.stav === REZ_REZERVOVANO)
    .map(r => ({ ...r, slot: slotyMap[r.slot_id] }))
    .filter(r => r.slot && r.slot.datum >= dnes);

  const zjednodus = r => ({
    id: r.id, jmeno: r.jmeno, kontakt_zpusob: r.kontakt_zpusob, telefon: r.telefon,
    datum: r.slot.datum, cas_od: r.slot.cas_od, cas_do: r.slot.cas_do,
  });

  const dnesni = aktivni.filter(r => r.slot.datum === dnes)
    .sort((a, b) => a.slot.cas_od.localeCompare(b.slot.cas_od)).map(zjednodus);
  const tydenni = aktivni.filter(r => r.slot.datum > dnes && r.slot.datum <= zaTyden)
    .sort((a, b) => a.slot.datum !== b.slot.datum ? a.slot.datum.localeCompare(b.slot.datum) : a.slot.cas_od.localeCompare(b.slot.cas_od))
    .map(zjednodus);

  return jsonResp({ dnes: dnesni, tyden: tydenni }, 200, hdrs);
}

/** GET /api/admin/lektor/{email} — historie lektora (Fáze 5, funkce 6) */
async function handleAdminLektorHistorie(env, aud, emailParam, hdrs) {
  const emailNorm = decodeURIComponent(emailParam).trim().toLowerCase();
  if (!emailNorm) return jsonResp({ chyba: 'Chybí e-mail lektora.' }, 400, hdrs);

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slotyMap = Object.fromEntries(sloty.map(s => [s.id, s]));
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);

  const historie = rezervace
    .filter(r => r.auditorka_id === aud.id && r.email.toLowerCase() === emailNorm)
    .map(r => ({ ...r, slot: slotyMap[r.slot_id] }))
    .sort((a, b) => (b.slot?.datum || '').localeCompare(a.slot?.datum || ''));

  return jsonResp({
    email: emailNorm,
    pocet: historie.length,
    rezervace: historie.map(r => ({
      id: r.id, datum: r.slot?.datum || '', cas_od: r.slot?.cas_od || '', cas_do: r.slot?.cas_do || '',
      kontakt_zpusob: r.kontakt_zpusob, stav: r.stav, typ_cinnosti: r.typ_cinnosti,
      firma: r.firma, vysledek: r.vysledek, poznamka: r.poznamka,
    })),
  }, 200, hdrs);
}

/**
 * Sestaví a odešle potvrzovací e-mail s .ics pozvánkou pro danou rezervaci (§8 zadání).
 * Při volbě Teams se použije pevný osobní Teams odkaz auditorky z listu Auditorky.
 * Při volbě telefon se do pozvánky napíše "proběhne telefonicky" + telefon lektora.
 *
 * Používá se automaticky hned po vytvoření rezervace (viz handlePostRezervace) —
 * proto nepotřebuje admin session a chyby vyhazuje jako výjimku (volající si je odchytí).
 */
async function posliPotvrzeni(env, rez, slot) {
  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const auditorkaFull = auditorky.find(a => a.id === rez.auditorka_id);
  if (!auditorkaFull || !auditorkaFull.email) {
    throw new Error(`Auditorka ${rez.auditorka_id} nemá v listu Auditorky vyplněný e-mail.`);
  }

  const jeTeams = rez.kontakt_zpusob === KONTAKT_TEAMS;
  if (jeTeams && !auditorkaFull.teams_odkaz) {
    throw new Error(`Auditorka ${rez.auditorka_id} nemá v listu Auditorky vyplněný Teams odkaz (sloupec teams_odkaz).`);
  }

  const datumTxt = formatDatumCz(slot.datum);
  const casTxt = `${slot.cas_od}–${slot.cas_do}`;

  // Odkaz na samoobslužné zrušení/přesun termínu (Fáze 5, funkce 1) — funguje bez přihlášení,
  // jen díky náhodnému tokenu uloženému u rezervace. Když ALLOWED_ORIGIN chybí, odkaz se
  // v e-mailu prostě nezobrazí (email jinak funguje dál).
  const samoobsluhaOdkaz = env.ALLOWED_ORIGIN && rez.token
    ? `${env.ALLOWED_ORIGIN.replace(/\/$/, '')}/moje-rezervace/?token=${encodeURIComponent(rez.token)}`
    : null;
  const samoobsluhaHtml = samoobsluhaOdkaz
    ? `<p style="margin-top:1.25rem;">Potřebujete termín zrušit nebo přesunout na jiný čas?
        <a href="${escHtml(samoobsluhaOdkaz)}">Klikněte sem</a> (bez přihlašování).</p>`
    : '';

  let predmet, misto, popis, html;
  if (jeTeams) {
    predmet = `Schůzka: pohovor s ${auditorkaFull.jmeno}`;
    misto = auditorkaFull.teams_odkaz;
    popis = `Schůzka přes MS Teams.\nOdkaz na schůzku: ${auditorkaFull.teams_odkaz}\n\nTermín: ${datumTxt}, ${casTxt}`;
    html = `<p>Dobrý den ${escHtml(rez.jmeno)},</p>
      <p>Vaše schůzka s <strong>${escHtml(auditorkaFull.jmeno)}</strong> je naplánována na
      <strong>${datumTxt}, ${casTxt}</strong>.</p>
      <p>Schůzka proběhne přes MS Teams na odkazu:<br>
      <a href="${escHtml(auditorkaFull.teams_odkaz)}">${escHtml(auditorkaFull.teams_odkaz)}</a></p>
      <p>V příloze najdete pozvánku do kalendáře (soubor .ics) — otevřením se přidá do vašeho kalendáře
      (funguje v Google Kalendáři i v Outlooku).</p>
      ${samoobsluhaHtml}`;
  } else {
    predmet = `Telefonický pohovor s ${auditorkaFull.jmeno}`;
    misto = 'Telefonicky';
    popis = `Proběhne telefonicky.\nTelefonní číslo lektora: ${rez.telefon}\n\nTermín: ${datumTxt}, ${casTxt}`;
    html = `<p>Dobrý den ${escHtml(rez.jmeno)},</p>
      <p>Váš termín s <strong>${escHtml(auditorkaFull.jmeno)}</strong> je naplánován na
      <strong>${datumTxt}, ${casTxt}</strong>.</p>
      <p>Auditorka vás bude kontaktovat telefonicky na čísle, které jste uvedli při rezervaci
      (${escHtml(rez.telefon)}).</p>
      <p>V příloze najdete pozvánku do kalendáře (soubor .ics).</p>
      ${samoobsluhaHtml}`;
  }

  const ics = buildIcs({
    uid: `${rez.id}@rezervacni-system`,
    datum: slot.datum, casOd: slot.cas_od, casDo: slot.cas_do,
    summary: predmet, description: popis, location: misto,
    organizerEmail: auditorkaFull.email, organizerName: auditorkaFull.jmeno,
    attendeeEmail: rez.email, attendeeName: rez.jmeno,
  });

  await sendEmail(env, {
    to: rez.email,
    cc: auditorkaFull.email,
    fromEmail: auditorkaFull.email,
    fromName: auditorkaFull.jmeno,
    subject: predmet,
    html,
    icsContent: ics,
    icsFilename: 'schuzka.ics',
  });

  // U Teams schůzky uložíme použitý odkaz i k samotné rezervaci (pro přehled v adminu)
  if (jeTeams) {
    const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
    if (rowNum > 0) {
      await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, { ...rez, teams_odkaz: auditorkaFull.teams_odkaz }));
    }
  }
}

/**
 * POST /api/admin/rezervace/:id/uskutecneno — §10/§11 zadání.
 * V jednom kroku: přiřadí typ činnosti (+ firma / kurz / ostatní kompetence u Kontroly
 * hodnocení), zapíše čas pro mzdu a výsledek/poznámku, a překlopí rezervaci do výkazu.
 */
async function handleAdminUskutecneno(req, env, aud, rezId, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }

  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);
  if (rez.stav !== REZ_REZERVOVANO) return jsonResp({ chyba: 'Lze uskutečnit jen aktivní (dosud nevyřízenou) rezervaci.' }, 409, hdrs);

  const typ = b.typ_cinnosti;
  if (typ !== TYP_VSTUPNI && typ !== TYP_KONTROLA) {
    return jsonResp({ chyba: 'Vyberte typ činnosti (Vstupní audit / Kontrola hodnocení).' }, 422, hdrs);
  }

  const chybaCas = validateCasProMzdu(b.cas_pro_mzdu_min);
  if (chybaCas) return jsonResp({ chyba: chybaCas }, 422, hdrs);

  const vysledek = sanitize(b.vysledek || '');
  if (!vysledek) return jsonResp({ chyba: 'Vyplňte výsledek / poznámku pro výkaz.' }, 422, hdrs);

  const jeKontrola = typ === TYP_KONTROLA;

  const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);

  const updated = {
    ...rez,
    typ_cinnosti: typ,
    firma: sanitize(b.firma || '').slice(0, 200),
    // Kurz a "ostatní kompetence v pořádku" dávají smysl jen u Kontroly hodnocení
    kurz: jeKontrola ? sanitize(b.kurz || '').slice(0, 200) : '',
    ostatni_kompetence_ok: jeKontrola ? (b.ostatni_kompetence_ok ? 'ano' : 'ne') : '',
    stav: REZ_USKUTECNENO,
    vysledek,
    cas_pro_mzdu_min: String(parseInt(b.cas_pro_mzdu_min, 10)),
  };
  await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, updated));

  return jsonResp({ ok: true }, 200, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — ADMINISTRATIVA (ruční položky výkazu, §11)
// ════════════════════════════════════════════════════════════════

/** GET /api/admin/administrativa */
async function handleAdminGetAdministrativa(env, aud, hdrs) {
  const polozky = await readSheet(env, SHEET_ADMINISTRATIVA, COLS_ADMINISTRATIVA);
  const moje = polozky
    .filter(p => p.auditorka_id === aud.id)
    .sort((a, b) => b.datum.localeCompare(a.datum));
  return jsonResp({ polozky: moje }, 200, hdrs);
}

/** POST /api/admin/administrativa — ruční přidání položky (např. "předchystávání tabulek") */
async function handleAdminCreateAdministrativa(req, env, aud, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const { datum, vysledek_poznamka, cas_pro_mzdu_min, firma } = b;

  if (!datum || !/^\d{4}-\d{2}-\d{2}$/.test(datum)) return jsonResp({ chyba: 'Zadejte platné datum.' }, 422, hdrs);
  const chybaCas = validateCasProMzdu(cas_pro_mzdu_min);
  if (chybaCas) return jsonResp({ chyba: chybaCas }, 422, hdrs);
  const popis = sanitize(vysledek_poznamka || '');
  if (!popis) return jsonResp({ chyba: 'Vyplňte popis úkonu.' }, 422, hdrs);

  const id = genId();
  await sheetsAppend(env, SHEET_ADMINISTRATIVA, objToRow(COLS_ADMINISTRATIVA, {
    id, auditorka_id: aud.id, datum, vysledek_poznamka: popis,
    cas_pro_mzdu_min: String(parseInt(cas_pro_mzdu_min, 10)), firma: sanitize(firma || '').slice(0, 200),
  }));
  return jsonResp({ ok: true, id }, 201, hdrs);
}

// ════════════════════════════════════════════════════════════════
// HANDLERY — VÝKAZY A EXPORT (§11 zadání — 8 sloupců, 3 kategorie, po měsících)
// ════════════════════════════════════════════════════════════════

function round2(v) { return Math.round(v * 100) / 100; }

/** Sestaví řádky výkazu pro danou auditorku a měsíc (YYYY-MM). Sdíleno mezi /vykazy a /export. */
async function sestavVykazRadky(env, aud, mesic) {
  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const auditorkaFull = auditorky.find(a => a.id === aud.id);
  const sazba = parseFloat(auditorkaFull?.sazba_60min || '0') || 0;

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slotyMap = Object.fromEntries(sloty.map(s => [s.id, s]));

  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const administrativa = await readSheet(env, SHEET_ADMINISTRATIVA, COLS_ADMINISTRATIVA);

  const radky = [];

  rezervace
    .filter(r => r.auditorka_id === aud.id && r.stav === REZ_USKUTECNENO)
    .forEach(r => {
      const slot = slotyMap[r.slot_id];
      if (!slot) return;
      if (mesic && slot.datum.slice(0, 7) !== mesic) return;
      const min = parseInt(r.cas_pro_mzdu_min, 10) || 0;
      radky.push({
        datum: slot.datum,
        typ_agendy: r.typ_cinnosti || '—',
        jmeno: r.jmeno,
        firma: r.firma || '',
        cas_od_do: `${slot.cas_od}–${slot.cas_do}`,
        vysledek_poznamka: r.vysledek || '',
        kurz: r.kurz || '',
        ostatni_kompetence_ok: r.ostatni_kompetence_ok || '',
        cas_pro_mzdu_min: min,
        k_vyplate: round2(min / 60 * sazba),
      });
    });

  administrativa
    .filter(p => p.auditorka_id === aud.id && (!mesic || p.datum.slice(0, 7) === mesic))
    .forEach(p => {
      const min = parseInt(p.cas_pro_mzdu_min, 10) || 0;
      radky.push({
        datum: p.datum,
        typ_agendy: 'Administrativa',
        jmeno: '',
        firma: p.firma || '',
        cas_od_do: '',
        vysledek_poznamka: p.vysledek_poznamka || '',
        kurz: '',
        ostatni_kompetence_ok: '',
        cas_pro_mzdu_min: min,
        k_vyplate: round2(min / 60 * sazba),
      });
    });

  radky.sort((a, b) => a.datum.localeCompare(b.datum));
  return { radky, auditorkaFull, sazba };
}

/** GET /api/admin/vykazy?mesic=RRRR-MM — měsíční výkaz ve 3 kategoriích */
async function handleAdminVykazy(req, env, aud, hdrs) {
  const mesic = new URL(req.url).searchParams.get('mesic') || new Date().toISOString().slice(0, 7);
  if (!/^\d{4}-\d{2}$/.test(mesic)) return jsonResp({ chyba: 'Neplatný formát měsíce (očekává se RRRR-MM).' }, 400, hdrs);

  const { radky, auditorkaFull, sazba } = await sestavVykazRadky(env, aud, mesic);

  const souhrn = {
    [TYP_VSTUPNI]: { pocet: 0, minut: 0, castka: 0 },
    [TYP_KONTROLA]: { pocet: 0, minut: 0, castka: 0 },
    'Administrativa': { pocet: 0, minut: 0, castka: 0 },
  };
  let celkemKVyplate = 0;
  // Rozpad podle firmy/klienta (Fáze 5, funkce 7) — sčítá se ze stejných řádků výkazu
  const podleFirmy = {};
  radky.forEach(r => {
    if (souhrn[r.typ_agendy]) {
      souhrn[r.typ_agendy].pocet++;
      souhrn[r.typ_agendy].minut += r.cas_pro_mzdu_min;
      souhrn[r.typ_agendy].castka = round2(souhrn[r.typ_agendy].castka + r.k_vyplate);
    }
    celkemKVyplate = round2(celkemKVyplate + r.k_vyplate);

    const klic = r.firma || '(bez firmy)';
    if (!podleFirmy[klic]) podleFirmy[klic] = { pocet: 0, minut: 0, castka: 0 };
    podleFirmy[klic].pocet++;
    podleFirmy[klic].minut += r.cas_pro_mzdu_min;
    podleFirmy[klic].castka = round2(podleFirmy[klic].castka + r.k_vyplate);
  });

  return jsonResp({
    hlavicka: {
      metodik: auditorkaFull?.jmeno || aud.jmeno,
      obdobi: mesic,
      jazyk: auditorkaFull?.jazyk || '',
      sazba_60min: sazba,
      celkem_k_vyplate: celkemKVyplate,
    },
    radky,
    souhrn,
    podle_firmy: podleFirmy,
  }, 200, hdrs);
}

/** GET /api/admin/vykazy/srovnani?rok=RRRR — srovnání měsíců v roce (Fáze 5, funkce 7) */
async function handleAdminVykazySrovnani(req, env, aud, hdrs) {
  const rok = new URL(req.url).searchParams.get('rok') || String(new Date().getFullYear());
  if (!/^\d{4}$/.test(rok)) return jsonResp({ chyba: 'Neplatný rok (očekává se RRRR).' }, 400, hdrs);

  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const auditorkaFull = auditorky.find(a => a.id === aud.id);
  const sazba = parseFloat(auditorkaFull?.sazba_60min || '0') || 0;

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slotyMap = Object.fromEntries(sloty.map(s => [s.id, s]));
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const administrativa = await readSheet(env, SHEET_ADMINISTRATIVA, COLS_ADMINISTRATIVA);

  // Připravíme prázdný souhrn pro všech 12 měsíců, ať srovnání ukáže i měsíce bez záznamů
  const mesice = {};
  for (let m = 1; m <= 12; m++) {
    const klic = `${rok}-${String(m).padStart(2, '0')}`;
    mesice[klic] = { mesic: klic, pocet: 0, minut: 0, castka: 0 };
  }

  rezervace
    .filter(r => r.auditorka_id === aud.id && r.stav === REZ_USKUTECNENO)
    .forEach(r => {
      const slot = slotyMap[r.slot_id];
      if (!slot || slot.datum.slice(0, 4) !== rok) return;
      const klic = slot.datum.slice(0, 7);
      if (!mesice[klic]) return;
      const min = parseInt(r.cas_pro_mzdu_min, 10) || 0;
      mesice[klic].pocet++;
      mesice[klic].minut += min;
      mesice[klic].castka = round2(mesice[klic].castka + round2(min / 60 * sazba));
    });

  administrativa
    .filter(p => p.auditorka_id === aud.id && p.datum.slice(0, 4) === rok)
    .forEach(p => {
      const klic = p.datum.slice(0, 7);
      if (!mesice[klic]) return;
      const min = parseInt(p.cas_pro_mzdu_min, 10) || 0;
      mesice[klic].pocet++;
      mesice[klic].minut += min;
      mesice[klic].castka = round2(mesice[klic].castka + round2(min / 60 * sazba));
    });

  return jsonResp({ rok, mesice: Object.values(mesice) }, 200, hdrs);
}

/** GET /api/admin/export?mesic=RRRR-MM — CSV export ve stejném rozvržení jako výkaz (bez parametru = export všeho) */
async function handleAdminExport(req, env, aud, hdrs) {
  const mesic = new URL(req.url).searchParams.get('mesic') || null;
  const { radky, auditorkaFull, sazba } = await sestavVykazRadky(env, aud, mesic);

  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;

  const hlavickaRadek = [
    `Metodik: ${auditorkaFull?.jmeno || ''}`,
    `Jazyk: ${auditorkaFull?.jazyk || ''}`,
    `Sazba Kč/60 min: ${sazba}`,
    `Období: ${mesic || 'vše'}`,
  ].join('   |   ');

  const celkem = radky.reduce((s, r) => s + r.k_vyplate, 0);

  const radkyCsv = [
    hlavickaRadek,
    '',
    'Datum,Typ agendy,Jméno,Firma,Čas od-do,Výsledek/poznámka,Čas pro mzdu (min),K výplatě (Kč)',
    ...radky.map(r => [r.datum, r.typ_agendy, r.jmeno, r.firma, r.cas_od_do, r.vysledek_poznamka, r.cas_pro_mzdu_min, r.k_vyplate].map(esc).join(',')),
    '',
    `,,,,,,Celkem k výplatě:,${round2(celkem)}`,
  ];

  return new Response(radkyCsv.join('\r\n'), {
    status: 200,
    headers: {
      ...hdrs,
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="vykaz-${mesic || 'vse'}.csv"`,
    },
  });
}

// ════════════════════════════════════════════════════════════════
// HLAVNÍ HANDLER
// ════════════════════════════════════════════════════════════════

export default {
  async fetch(req, env, ctx) {
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
        return await handleGetSloty(req, env, hdrs);
      }

      if (method === 'POST' && path === '/api/rezervace') {
        if (!checkRateLimit(ip, 'rezervace', 5, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handlePostRezervace(req, env, hdrs, ctx);
      }

      // ── Samoobsluha lektora přes token (Fáze 5, funkce 1) ──
      // Společný rate limit "samoobsluha" — token nejde uhodnout, ale i tak omezíme zkoušení nazdařbůh.
      const mTokenSloty = path.match(/^\/api\/rezervace\/([^/]+)\/sloty$/);
      if (mTokenSloty && method === 'GET') {
        if (!checkRateLimit(ip, 'samoobsluha', 30, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handleGetVolneSlotyToken(env, mTokenSloty[1], hdrs);
      }
      const mTokenZrusit = path.match(/^\/api\/rezervace\/([^/]+)\/zrusit$/);
      if (mTokenZrusit && method === 'POST') {
        if (!checkRateLimit(ip, 'samoobsluha', 30, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handleTokenZrusit(env, mTokenZrusit[1], hdrs);
      }
      const mTokenPresunout = path.match(/^\/api\/rezervace\/([^/]+)\/presunout$/);
      if (mTokenPresunout && method === 'POST') {
        if (!checkRateLimit(ip, 'samoobsluha', 30, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handleTokenPresunout(req, env, mTokenPresunout[1], hdrs, ctx);
      }
      const mTokenDetail = path.match(/^\/api\/rezervace\/([^/]+)$/);
      if (mTokenDetail && method === 'GET') {
        if (!checkRateLimit(ip, 'samoobsluha', 30, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handleGetRezervaceToken(env, mTokenDetail[1], hdrs);
      }

      // ── Admin přihlášení ───────────────────────────────────

      if (method === 'POST' && path === '/api/admin/login') {
        if (!checkRateLimit(ip, 'login', 10, 300_000)) {
          return jsonResp({ chyba: 'Příliš mnoho pokusů o přihlášení. Zkuste to za 5 minut.' }, 429, hdrs);
        }
        return await handleLogin(req, env, hdrs);
      }

      if (method === 'POST' && path === '/api/admin/logout') {
        return handleLogout(hdrs);
      }

      if (method === 'GET' && path === '/api/admin/me') {
        return await handleMe(req, env, hdrs);
      }

      // ── Chráněné admin endpointy ───────────────────────────

      // Všechny /api/admin/* cesty (kromě výše) vyžadují session
      if (!path.startsWith('/api/admin/')) {
        return jsonResp({ chyba: 'Endpoint nenalezen.' }, 404, hdrs);
      }

      const aud = await requireAuth(req, env);
      if (!aud) return jsonResp({ chyba: 'Přihlášení vyžadováno.' }, 401, hdrs);

      // CSRF ochrana na mutace
      if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        if (!(await verifyCsrf(req, env))) {
          return jsonResp({ chyba: 'Neplatný bezpečnostní token. Obnovte stránku a zkuste znovu.' }, 403, hdrs);
        }
      }

      if (path === '/api/admin/change-password' && method === 'POST') {
        return await handleChangePassword(req, env, aud, hdrs);
      }

      // Sloty
      if (path === '/api/admin/sloty/bulk' && method === 'POST') {
        return await handleAdminCreateSlotsBulk(req, env, aud, hdrs);
      }
      if (path === '/api/admin/sloty') {
        if (method === 'GET')  return await handleAdminGetSloty(env, aud, hdrs);
        if (method === 'POST') return await handleAdminCreateSlot(req, env, aud, hdrs);
      }
      const mSlot = path.match(/^\/api\/admin\/sloty\/([^/]+)$/);
      if (mSlot) {
        if (method === 'PUT')    return await handleAdminUpdateSlot(req, env, aud, mSlot[1], hdrs);
        if (method === 'DELETE') return await handleAdminDeleteSlot(env, aud, mSlot[1], hdrs);
      }

      // Rezervace — nejdřív konkrétnější cesty (/zrusit, /uskutecneno, /nedostavil-se), pak obecné
      if (path === '/api/admin/rezervace') {
        if (method === 'GET')  return await handleAdminGetRezervace(env, aud, hdrs);
        if (method === 'POST') return await handleAdminCreateRezervace(req, env, aud, hdrs, ctx); // Fáze 5, funkce 3
      }
      const mZrush = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/zrusit$/);
      if (mZrush && method === 'PUT') {
        return await handleAdminZrushRezervaci(env, aud, mZrush[1], hdrs);
      }
      const mUskut = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/uskutecneno$/);
      if (mUskut && method === 'POST') {
        return await handleAdminUskutecneno(req, env, aud, mUskut[1], hdrs);
      }
      const mNedostavil = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/nedostavil-se$/);
      if (mNedostavil && method === 'PUT') {
        return await handleAdminNedostavilSe(env, aud, mNedostavil[1], hdrs); // Fáze 5, funkce 2
      }

      // Denní/týdenní přehled agendy (Fáze 5, funkce 4)
      if (path === '/api/admin/prehled' && method === 'GET') {
        return await handleAdminPrehled(env, aud, hdrs);
      }

      // Historie lektora podle e-mailu (Fáze 5, funkce 6)
      const mLektor = path.match(/^\/api\/admin\/lektor\/([^/]+)$/);
      if (mLektor && method === 'GET') {
        return await handleAdminLektorHistorie(env, aud, mLektor[1], hdrs);
      }

      // Administrativa
      if (path === '/api/admin/administrativa') {
        if (method === 'GET')  return await handleAdminGetAdministrativa(env, aud, hdrs);
        if (method === 'POST') return await handleAdminCreateAdministrativa(req, env, aud, hdrs);
      }

      // Výkazy a export
      if (path === '/api/admin/vykazy/srovnani' && method === 'GET') return await handleAdminVykazySrovnani(req, env, aud, hdrs); // Fáze 5, funkce 7
      if (path === '/api/admin/vykazy' && method === 'GET') return await handleAdminVykazy(req, env, aud, hdrs);
      if (path === '/api/admin/export' && method === 'GET') return await handleAdminExport(req, env, aud, hdrs);

      return jsonResp({ chyba: 'Endpoint nenalezen.' }, 404, hdrs);

    } catch (err) {
      // Loguje chybu do Cloudflare Observability (viditelné jen v dashboardu)
      console.error('Worker error:', err?.message || err);
      return jsonResp({ chyba: 'Interní chyba serveru.' }, 500, hdrs);
    }
  },
};
