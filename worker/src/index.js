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
 *   APPS_SCRIPT_URL       – URL nasazeného Google Apps Script Web App, který posílá
 *                            potvrzovací e-maily (+ .ics) přes Gmail auditorky. Viz SETUP.md krok 4.
 *   APPS_SCRIPT_SECRET    – sdílené heslo mezi Workerem a Apps Scriptem (ochrana proti zneužití
 *                            Apps Script URL cizí osobou k rozesílání e-mailů z vašeho Gmailu)
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
];
const COLS_ADMINISTRATIVA = ['id', 'auditorka_id', 'datum', 'vysledek_poznamka', 'cas_pro_mzdu_min', 'firma'];

// Stavy slotu
const STAV_VOLNY    = 'volny';
const STAV_OBSAZENY = 'obsazeny';
const STAV_ZRUSEN   = 'zrusen';

// Stavy rezervace
const REZ_REZERVOVANO = 'rezervovano';
const REZ_USKUTECNENO = 'uskutecneno';
const REZ_ZRUSENO     = 'zruseno';

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
// E-MAIL A KALENDÁŘOVÁ POZVÁNKA (.ics) — bez Microsoftu, přes Gmail (Google Apps Script)
// ════════════════════════════════════════════════════════════════

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
 * Odešle e-mail (volitelně s .ics přílohou) přes Google Apps Script Web App,
 * který běží pod Gmail účtem auditorky (viz SETUP.md krok 4 a soubor apps-script/rezervace-email.gs).
 * Worker sám žádné přihlašovací údaje ke Gmailu nemá — jen zavolá tuto webovou adresu
 * se sdíleným heslem (APPS_SCRIPT_SECRET), a odeslání zajistí skript v Google účtu.
 */
async function sendEmail(env, { to, cc, subject, html, icsContent, icsFilename }) {
  if (!env.APPS_SCRIPT_URL) {
    throw new Error('E-mailová služba není nastavená (chybí secret APPS_SCRIPT_URL). Viz SETUP.md.');
  }
  const payload = {
    secret: env.APPS_SCRIPT_SECRET || '',
    to: Array.isArray(to) ? to.join(',') : to,
    subject,
    html,
  };
  if (cc) payload.cc = Array.isArray(cc) ? cc.join(',') : cc;
  if (icsContent) {
    payload.icsContent = icsContent;
    payload.icsFilename = icsFilename || 'schuzka.ics';
  }

  const r = await fetch(env.APPS_SCRIPT_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
    redirect: 'follow',
  });
  if (!r.ok) throw new Error(`Apps Script chyba ${r.status}: ${await r.text()}`);

  const data = await r.json().catch(() => ({}));
  if (!data.ok) throw new Error(data.error || 'Apps Script vrátil neznámou chybu.');
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
async function handlePostRezervace(req, env, hdrs) {
  let body;
  try { body = await req.json(); }
  catch { return jsonResp({ chyba: 'Neplatný formát požadavku.' }, 400, hdrs); }

  const { slot_id, jmeno, email, kontakt_zpusob, telefon, poznamka } = body;

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

  await sheetsAppend(env, SHEET_REZERVACE, objToRow(COLS_REZERVACE, {
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
  }));

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

/**
 * PUT /api/admin/rezervace/:id — auditorka přiřadí typ činnosti (a s ním
 * související pole firma / kurz / ostatní kompetence v pořádku).
 * Stav rezervace (zrušit / uskutečněno) se řeší dedikovanými endpointy níže,
 * aby v jedné metodě nešlo omylem přepsat business logiku (uvolnění slotu apod.).
 */
async function handleAdminUpdateRezervace(req, env, aud, rezId, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);

  const typ = b.typ_cinnosti;
  if (typ !== undefined && typ !== '' && typ !== TYP_VSTUPNI && typ !== TYP_KONTROLA) {
    return jsonResp({ chyba: 'Neplatný typ činnosti.' }, 422, hdrs);
  }

  const novyTyp = typ !== undefined ? typ : rez.typ_cinnosti;
  const jeKontrola = novyTyp === TYP_KONTROLA;

  const updated = {
    ...rez,
    typ_cinnosti: novyTyp,
    firma: b.firma !== undefined ? sanitize(b.firma).slice(0, 200) : rez.firma,
    // Kurz a "ostatní kompetence v pořádku" dávají smysl jen u Kontroly hodnocení
    kurz: jeKontrola ? sanitize(b.kurz || rez.kurz || '').slice(0, 200) : '',
    ostatni_kompetence_ok: jeKontrola ? (b.ostatni_kompetence_ok !== undefined ? (b.ostatni_kompetence_ok ? 'ano' : 'ne') : rez.ostatni_kompetence_ok) : '',
  };

  const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);
  await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, updated));

  return jsonResp({ ok: true }, 200, hdrs);
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

/**
 * POST /api/admin/rezervace/:id/naplanovat — §8 zadání:
 * pošle potvrzovací e-mail (+ .ics pozvánku do kalendáře) lektorovi (kopie auditorce).
 * Při volbě Teams se použije pevný osobní Teams odkaz auditorky z listu Auditorky.
 * Při volbě telefon se do pozvánky napíše "proběhne telefonicky" + telefon lektora.
 */
async function handleAdminNaplanovat(env, aud, rezId, hdrs) {
  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);
  if (rez.stav === REZ_ZRUSENO) return jsonResp({ chyba: 'Rezervace je zrušená, nelze naplánovat.' }, 409, hdrs);

  const sloty = await readSheet(env, SHEET_SLOTY, COLS_SLOTY);
  const slot = sloty.find(s => s.id === rez.slot_id);
  if (!slot) return jsonResp({ chyba: 'Termín rezervace nenalezen.' }, 404, hdrs);

  const auditorky = await readSheet(env, SHEET_AUDITORKY, COLS_AUDITORKY);
  const auditorkaFull = auditorky.find(a => a.id === aud.id);
  if (!auditorkaFull || !auditorkaFull.email) {
    return jsonResp({ chyba: 'Auditorka nemá v listu Auditorky vyplněný e-mail.' }, 422, hdrs);
  }

  const jeTeams = rez.kontakt_zpusob === KONTAKT_TEAMS;
  if (jeTeams && !auditorkaFull.teams_odkaz) {
    return jsonResp({ chyba: 'Auditorka nemá v listu Auditorky vyplněný Teams odkaz (sloupec teams_odkaz).' }, 422, hdrs);
  }

  const datumTxt = formatDatumCz(slot.datum);
  const casTxt = `${slot.cas_od}–${slot.cas_do}`;

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
      (funguje v Google Kalendáři i v Outlooku).</p>`;
  } else {
    predmet = `Telefonický pohovor s ${auditorkaFull.jmeno}`;
    misto = 'Telefonicky';
    popis = `Proběhne telefonicky.\nTelefonní číslo lektora: ${rez.telefon}\n\nTermín: ${datumTxt}, ${casTxt}`;
    html = `<p>Dobrý den ${escHtml(rez.jmeno)},</p>
      <p>Váš termín s <strong>${escHtml(auditorkaFull.jmeno)}</strong> je naplánován na
      <strong>${datumTxt}, ${casTxt}</strong>.</p>
      <p>Auditorka vás bude kontaktovat telefonicky na čísle, které jste uvedli při rezervaci
      (${escHtml(rez.telefon)}).</p>
      <p>V příloze najdete pozvánku do kalendáře (soubor .ics).</p>`;
  }

  const ics = buildIcs({
    uid: `${rez.id}@rezervacni-system`,
    datum: slot.datum, casOd: slot.cas_od, casDo: slot.cas_do,
    summary: predmet, description: popis, location: misto,
    organizerEmail: auditorkaFull.email, organizerName: auditorkaFull.jmeno,
    attendeeEmail: rez.email, attendeeName: rez.jmeno,
  });

  try {
    await sendEmail(env, {
      to: rez.email,
      cc: auditorkaFull.email,
      subject: predmet,
      html,
      icsContent: ics,
      icsFilename: 'schuzka.ics',
    });
  } catch (err) {
    return jsonResp({ chyba: `Nepodařilo se odeslat e-mail: ${err.message}` }, 502, hdrs);
  }

  // U Teams schůzky uložíme použitý odkaz i k samotné rezervaci (pro přehled v adminu)
  if (jeTeams) {
    const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
    if (rowNum > 0) {
      await sheetsUpdateRow(env, SHEET_REZERVACE, rowNum, objToRow(COLS_REZERVACE, { ...rez, teams_odkaz: auditorkaFull.teams_odkaz }));
    }
  }

  return jsonResp({ ok: true, zprava: 'E-mail s pozvánkou byl odeslán lektorovi (kopie vám).' }, 200, hdrs);
}

/**
 * POST /api/admin/rezervace/:id/uskutecneno — §10/§11 zadání:
 * překlopí rezervaci do výkazu. Vyžaduje, aby už byl přiřazený typ činnosti.
 */
async function handleAdminUskutecneno(req, env, aud, rezId, hdrs) {
  let b; try { b = await req.json(); } catch { return jsonResp({ chyba: 'Neplatný požadavek.' }, 400, hdrs); }

  const rezervace = await readSheet(env, SHEET_REZERVACE, COLS_REZERVACE);
  const rez = rezervace.find(r => r.id === rezId && r.auditorka_id === aud.id);
  if (!rez) return jsonResp({ chyba: 'Rezervace nenalezena.' }, 404, hdrs);
  if (rez.stav === REZ_ZRUSENO) return jsonResp({ chyba: 'Zrušenou rezervaci nelze označit jako uskutečněnou.' }, 409, hdrs);
  if (!rez.typ_cinnosti) return jsonResp({ chyba: 'Nejdřív přiřaďte typ činnosti (Vstupní audit / Kontrola hodnocení).' }, 422, hdrs);

  const chybaCas = validateCasProMzdu(b.cas_pro_mzdu_min);
  if (chybaCas) return jsonResp({ chyba: chybaCas }, 422, hdrs);

  const vysledek = sanitize(b.vysledek || '');
  if (!vysledek) return jsonResp({ chyba: 'Vyplňte výsledek / poznámku pro výkaz.' }, 422, hdrs);

  const rowNum = await findRowNum(env, SHEET_REZERVACE, rez.id);
  if (rowNum < 0) return jsonResp({ chyba: 'Interní chyba.' }, 500, hdrs);

  const updated = { ...rez, stav: REZ_USKUTECNENO, vysledek, cas_pro_mzdu_min: String(parseInt(b.cas_pro_mzdu_min, 10)) };
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
  radky.forEach(r => {
    if (souhrn[r.typ_agendy]) {
      souhrn[r.typ_agendy].pocet++;
      souhrn[r.typ_agendy].minut += r.cas_pro_mzdu_min;
      souhrn[r.typ_agendy].castka = round2(souhrn[r.typ_agendy].castka + r.k_vyplate);
    }
    celkemKVyplate = round2(celkemKVyplate + r.k_vyplate);
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
  }, 200, hdrs);
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
        return await handleGetSloty(req, env, hdrs);
      }

      if (method === 'POST' && path === '/api/rezervace') {
        if (!checkRateLimit(ip, 'rezervace', 5, 60_000)) {
          return jsonResp({ chyba: 'Příliš mnoho požadavků. Zkuste to za chvíli.' }, 429, hdrs);
        }
        return await handlePostRezervace(req, env, hdrs);
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

      // Rezervace — nejdřív konkrétnější cesty (/zrusit, /naplanovat, /uskutecneno), pak obecná /:id
      if (path === '/api/admin/rezervace' && method === 'GET') {
        return await handleAdminGetRezervace(env, aud, hdrs);
      }
      const mZrush = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/zrusit$/);
      if (mZrush && method === 'PUT') {
        return await handleAdminZrushRezervaci(env, aud, mZrush[1], hdrs);
      }
      const mNaplan = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/naplanovat$/);
      if (mNaplan && method === 'POST') {
        return await handleAdminNaplanovat(env, aud, mNaplan[1], hdrs);
      }
      const mUskut = path.match(/^\/api\/admin\/rezervace\/([^/]+)\/uskutecneno$/);
      if (mUskut && method === 'POST') {
        return await handleAdminUskutecneno(req, env, aud, mUskut[1], hdrs);
      }
      const mRez = path.match(/^\/api\/admin\/rezervace\/([^/]+)$/);
      if (mRez && method === 'PUT') {
        return await handleAdminUpdateRezervace(req, env, aud, mRez[1], hdrs);
      }

      // Administrativa
      if (path === '/api/admin/administrativa') {
        if (method === 'GET')  return await handleAdminGetAdministrativa(env, aud, hdrs);
        if (method === 'POST') return await handleAdminCreateAdministrativa(req, env, aud, hdrs);
      }

      // Výkazy a export
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
