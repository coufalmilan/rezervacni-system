/**
 * Generátor hashe hesla pro Cloudflare Worker
 *
 * Použití:
 *   node generate-hash.mjs vase-heslo
 *
 * Výsledek zkopírujte do Cloudflare secret AUDITORKA_PASSWORDS jako:
 *   {"1":"pbkdf2:...", "2":"pbkdf2:..."}
 *
 * Vyžaduje: Node.js 18+
 */

import { pbkdf2Sync, randomBytes } from 'crypto';

const heslo = process.argv[2];

if (!heslo) {
  console.error('');
  console.error('Použití:  node generate-hash.mjs vase-heslo');
  console.error('Příklad:  node generate-hash.mjs MojeHeslo123');
  console.error('');
  process.exit(1);
}

if (heslo.length < 8) {
  console.error('Heslo musí mít alespoň 8 znaků.');
  process.exit(1);
}

const salt = randomBytes(16);
const saltHex = salt.toString('hex');
const dk = pbkdf2Sync(heslo, salt, 100_000, 32, 'sha256');
const hashHex = dk.toString('hex');

const result = `pbkdf2:${saltHex}:${hashHex}`;

console.log('');
console.log('✅ Hash hesla (zkopírujte celý řetězec):');
console.log('');
console.log(result);
console.log('');
console.log('Příklad obsahu Cloudflare secret AUDITORKA_PASSWORDS:');
console.log(`{"1":"${result}"}`);
console.log('');
