#!/usr/bin/env node
/* Builds docs/index.html: the whole planner, encrypted with your passphrase.

   Usage:   node build.js
   You are asked for the passphrase (typing is hidden) and then asked again to confirm it.

   How it is protected: the passphrase is stretched with PBKDF2-SHA256 (600,000 rounds)
   into a 256-bit key, and the planner is encrypted with AES-256-GCM. The published page
   holds only the encrypted data and a small unlock form. Your browser decrypts it locally
   after you type the passphrase. Nothing is sent anywhere.
*/
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, 'src');
const OUT = process.env.PLANNER_OUT || path.join(__dirname, 'docs', 'index.html');
const ITER = 600000;
const MIN_LEN = 20;
const DEFAULT_REPO = 'B220067/planner-data';

function read(f) { return fs.readFileSync(path.join(SRC, f), 'utf8'); }
function swap(html, marker, replacement) {
  if (html.indexOf(marker) === -1) throw new Error('Marker not found in src/index.html: ' + marker);
  return html.split(marker).join(replacement);
}

// Fonts are embedded as data so the finished page works with no internet connection.
const FONT_FILE = path.join(SRC, 'fonts', 'PlusJakartaSans-latin-wght.woff2');
function fontData() { return 'data:font/woff2;base64,' + fs.readFileSync(FONT_FILE).toString('base64'); }
function inlineFonts(css) {
  return css.replace(/url\("fonts\/PlusJakartaSans-latin-wght\.woff2"\)/g, () => 'url("' + fontData() + '")');
}

function bundle(sync) {
  let html = read('index.html');
  html = swap(html, '/*__SYNC__*/null', sync ? JSON.stringify(sync) : 'null');
  const safe = (js) => js.replace(/<\/script/gi, '<\\/script');
  html = swap(html, '<link rel="stylesheet" href="style.css">', '<style>\n' + inlineFonts(read('style.css')) + '\n</style>');
  html = swap(html, '<script src="logic.js"></script>', '<script>\n' + safe(read('logic.js')) + '\n</script>');
  html = swap(html, '<script src="sync.js"></script>', '<script>\n' + safe(read('sync.js')) + '\n</script>');
  html = swap(html, '<script src="app.js"></script>', '<script>\n' + safe(read('app.js')) + '\n</script>');
  return html;
}

function askHidden(question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(question);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    let buf = '';
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n' || c === '\u0004') {
          stdin.setRawMode(false); stdin.pause(); stdin.removeListener('data', onData);
          process.stdout.write('\n');
          return resolve(buf);
        }
        if (c === '\u0003') { process.stdout.write('\n'); process.exit(130); }
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1);
        else buf += c;
      }
    };
    stdin.on('data', onData);
  });
}

async function getPassphrase() {
  if (process.env.PLANNER_PASSPHRASE) return process.env.PLANNER_PASSPHRASE; // for automated tests only
  if (!process.stdin.isTTY) throw new Error('Run this in a terminal so you can type the passphrase.');
  const a = await askHidden('Passphrase: ');
  const b = await askHidden('Type it again: ');
  if (a !== b) throw new Error('The two entries did not match. Nothing was built.');
  return a;
}

async function getToken() {
  if (process.env.PLANNER_TOKEN !== undefined) return process.env.PLANNER_TOKEN.trim(); // for automated tests only
  if (!process.stdin.isTTY) return '';
  return (await askHidden('GitHub token for sync (Enter to skip): ')).trim();
}

(async () => {
  const pass = (await getPassphrase()).normalize('NFKC').trim();
  if (pass.length < MIN_LEN) {
    throw new Error('Passphrase is too short (' + pass.length + ' characters). Use at least ' + MIN_LEN +
      ', for example 5 random words. Nothing was built.');
  }
  const token = await getToken();
  if (token && !/^[\w-]{20,}$/.test(token)) {
    throw new Error('That does not look like a GitHub token (it should start with github_pat_). Nothing was built.');
  }
  const repo = process.env.PLANNER_REPO || DEFAULT_REPO;
  const html = bundle(token ? { repo, token } : null);
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(pass, salt, ITER, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(html, 'utf8'), cipher.final()]);
  const ct = Buffer.concat([enc, cipher.getAuthTag()]); // WebCrypto expects the tag at the end
  const data = JSON.stringify({ iter: ITER, salt: salt.toString('base64'), iv: iv.toString('base64'), ct: ct.toString('base64') });
  const lockFont = '@font-face{font-family:"Plus Jakarta Sans";font-weight:200 800;font-display:swap;src:url("' + fontData() + '") format("woff2");}';
  const page = swap(swap(read('lock.html'), '/*__FONT__*/', lockFont), '/*__DATA__*/null', data);
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, page);
  console.log('Built ' + path.relative(process.cwd(), OUT) + ' (' + Math.round(page.length / 1024) + ' KB, encrypted).');
  console.log(token ? 'Sync is built in for ' + repo + ': any computer that unlocks the page connects by itself.' : 'No token given, so each computer will need the token pasted once (Sync at the top right).');
})().catch((e) => { console.error('\n' + e.message); process.exit(1); });
