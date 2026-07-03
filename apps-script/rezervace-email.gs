/**
 * Google Apps Script — e-mailová brána pro Rezervační systém
 *
 * Co to dělá:
 *   Cloudflare Worker sem pošle požadavek "pošli tenhle e-mail" a tenhle skript
 *   ho odešle přes Gmail účtu, pod kterým je nasazený (typicky Gmail auditorky
 *   nebo sdílený projektový Google účet — stejný, který se používá pro Google Sheets).
 *
 * Instalace: viz SETUP.md, krok 4 ("E-mailová služba — Google Apps Script").
 * Stručně:
 *   1. Na script.google.com založte nový projekt a vložte sem celý tento soubor.
 *   2. Řádek SHARED_SECRET níže nahraďte vlastním náhodným řetězcem (min. 32 znaků).
 *   3. Nasaďte jako Web App (Nasadit → Nové nasazení → Web App),
 *      "Spouštět jako": Já, "Kdo má přístup": Kdokoli.
 *   4. Zkopírovanou URL nasazení uložte do Cloudflare secret APPS_SCRIPT_URL.
 *   5. Stejný SHARED_SECRET uložte do Cloudflare secret APPS_SCRIPT_SECRET.
 */

// ⚠️ Nahraďte vlastním náhodným dlouhým řetězcem — musí se PŘESNĚ shodovat
// s hodnotou, kterou uložíte do Cloudflare secret APPS_SCRIPT_SECRET.
// Slouží k tomu, aby e-maily z vašeho Gmailu nemohl přes tuto adresu posílat kdokoliv cizí.
const SHARED_SECRET = 'SEM_VLOZTE_VLASTNI_NAHODNY_RETEZEC_MIN_32_ZNAKU';

/**
 * Zpracuje POST požadavek od Cloudflare Workeru a odešle e-mail.
 * Očekávané tělo požadavku (JSON):
 *   {
 *     "secret": "...",            // musí odpovídat SHARED_SECRET výše
 *     "to": "lektor@firma.cz",
 *     "cc": "auditorka@firma.cz", // volitelné
 *     "subject": "Předmět e-mailu",
 *     "html": "<p>Obsah e-mailu...</p>",
 *     "icsContent": "BEGIN:VCALENDAR...",  // volitelné — obsah .ics přílohy
 *     "icsFilename": "schuzka.ics"          // volitelné
 *   }
 */
function doPost(e) {
  try {
    const data = JSON.parse(e.postData.contents);

    // Ochrana: bez správného hesla skript nic neodešle
    if (data.secret !== SHARED_SECRET) {
      return jsonOutput({ ok: false, error: 'Neplatný přístupový klíč (secret).' });
    }
    if (!data.to || !data.subject) {
      return jsonOutput({ ok: false, error: 'Chybí povinné pole "to" nebo "subject".' });
    }

    const options = { htmlBody: data.html || '' };
    if (data.cc) options.cc = data.cc;

    // Pokud je přiložená kalendářová pozvánka (.ics), vytvoří se jako příloha e-mailu.
    // Typ "application/ics" (ne "text/calendar") schválně používáme proto, aby ji Gmail
    // vždy zobrazil jako běžnou přílohu ke stažení. Při typu "text/calendar" se Gmail
    // pokouší e-mail vykreslit jako speciální pozvánku s tlačítky Ano/Ne — a když se mu to
    // nepovede (např. kvůli "plovoucímu" času bez časového pásma), nezobrazí nic, ani
    // přílohu. Soubor .ics po otevření/stažení funguje stejně dobře v obou případech.
    if (data.icsContent) {
      const blob = Utilities.newBlob(data.icsContent, 'application/ics', data.icsFilename || 'schuzka.ics');
      options.attachments = [blob];
    }

    GmailApp.sendEmail(data.to, data.subject, '', options);

    return jsonOutput({ ok: true });
  } catch (err) {
    return jsonOutput({ ok: false, error: String(err && err.message ? err.message : err) });
  }
}

/** Pomocná funkce — vrátí JSON odpověď */
function jsonOutput(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * Testovací funkce — spusťte ručně tlačítkem "Spustit" v editoru Apps Scriptu,
 * abyste hned po nasazení schválili oprávnění ke Gmailu a ověřili, že vám e-mail dorazí.
 * (Odešle testovací e-mail sami sobě, na e-mail aktuálně přihlášeného Google účtu.)
 */
function testOdeslani() {
  const muj = Session.getActiveUser().getEmail();
  GmailApp.sendEmail(muj, 'Test — Rezervační systém', '', {
    htmlBody: '<p>Pokud tohle vidíte, e-mailová brána funguje správně. ✅</p>',
  });
}
