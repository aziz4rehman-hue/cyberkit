/* CyberKit — a browser-only security toolkit for learning.
 * Nothing you type is sent anywhere; every tool runs locally. */

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------------------------------------------------------------- matrix rain */

const canvas = $("matrix");
const ctx = canvas.getContext("2d");
const GLYPHS = "アカサタナハマヤラワ0123456789ABCDEF<>/{}$#";
let drops = [];
let matrixOn = true;

function resizeMatrix() {
  canvas.width = innerWidth;
  canvas.height = innerHeight;
  drops = Array(Math.ceil(canvas.width / 16)).fill(0).map(() => Math.random() * -50);
}

function drawMatrix() {
  if (matrixOn) {
    ctx.fillStyle = "rgba(2, 10, 4, 0.08)";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = "#00ff66";
    ctx.font = "15px monospace";
    drops.forEach((y, i) => {
      ctx.fillText(GLYPHS[Math.floor(Math.random() * GLYPHS.length)], i * 16, y * 16);
      drops[i] = y * 16 > canvas.height && Math.random() > 0.975 ? 0 : y + 1;
    });
  }
  setTimeout(() => requestAnimationFrame(drawMatrix), 45);
}

addEventListener("resize", resizeMatrix);
resizeMatrix();
drawMatrix();

/* ----------------------------------------------------------------------- tabs */

function openTab(name) {
  document.querySelectorAll("nav button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  document.querySelectorAll(".panel").forEach((p) => p.classList.toggle("active", p.id === name));
  if (name === "terminal") $("term-in").focus();
}

$("tabs").addEventListener("click", (e) => {
  if (e.target.dataset.tab) openTab(e.target.dataset.tab);
});

/* --------------------------------------------------------- common passwords */

const COMMON = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567", "111111",
  "123123", "abc123", "password1", "1234", "iloveyou", "1q2w3e4r", "000000", "qwerty123",
  "admin", "letmein", "welcome", "monkey", "dragon", "football", "baseball", "sunshine",
  "princess", "shadow", "master", "superman", "trustno1", "hello", "freedom", "whatever",
  "qazwsx", "michael", "654321", "starwars", "passw0rd", "login", "solo", "hunter2",
  "pakistan", "secret", "root", "toor", "changeme", "default", "guest", "test", "matrix", "hacker",
];

/* ------------------------------------------------------------------ hashing */

function md5(bytes) {
  const S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  const K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);
  const len = bytes.length;
  const blocks = ((len + 8) >>> 6) + 1;
  const w = new Uint32Array(blocks * 16);
  for (let i = 0; i < len; i++) w[i >> 2] |= bytes[i] << ((i % 4) * 8);
  w[len >> 2] |= 0x80 << ((len % 4) * 8);
  w[blocks * 16 - 2] = (len * 8) >>> 0;
  w[blocks * 16 - 1] = Math.floor((len * 8) / 2 ** 32);

  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let blk = 0; blk < blocks; blk++) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + w[blk * 16 + g]) >>> 0;
      const s = S[(i >> 4) * 4 + (i % 4)];
      A = D; D = C; C = B;
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  return [a0, b0, c0, d0]
    .map((v) => [0, 8, 16, 24].map((sh) => ((v >>> sh) & 255).toString(16).padStart(2, "0")).join(""))
    .join("");
}

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hashAll(text) {
  const data = enc.encode(text);
  const out = { "MD5": md5(data) };
  for (const alg of ["SHA-1", "SHA-256", "SHA-384", "SHA-512"]) {
    out[alg] = toHex(await crypto.subtle.digest(alg, data));
  }
  return out;
}

function identifyHash(h) {
  h = h.trim();
  const prefixes = [
    [/^\$2[abxy]\$\d{2}\$/, "bcrypt  (strong, slow — good for passwords)"],
    [/^\$argon2(id|i|d)\$/, "Argon2  (modern, recommended for passwords)"],
    [/^\$6\$/, "SHA-512 crypt (Linux /etc/shadow)"],
    [/^\$5\$/, "SHA-256 crypt"],
    [/^\$1\$/, "MD5 crypt (legacy Linux)"],
    [/^\$apr1\$/, "Apache MD5 (htpasswd)"],
    [/^\$P\$|^\$H\$/, "phpass (WordPress / phpBB)"],
    [/^scrypt:|^\$scrypt\$/, "scrypt"],
  ];
  for (const [re, name] of prefixes) if (re.test(h)) return [name];
  if (!/^[0-9a-f]+$/i.test(h)) {
    if (/^[A-Za-z0-9+/]+=*$/.test(h)) return ["Not hex — looks like Base64. Try decoding it in the cipher lab."];
    return ["Unknown format"];
  }
  const byLen = {
    8: ["CRC32", "Adler-32"],
    16: ["MySQL 3.x", "Half MD5"],
    32: ["MD5", "NTLM (Windows)", "MD4"],
    40: ["SHA-1", "RIPEMD-160", "MySQL 5 (without *)"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "Whirlpool", "BLAKE2b"],
  };
  return byLen[h.length] || [`Unknown hex digest (${h.length} chars)`];
}

async function crackHash(h) {
  h = h.trim().toLowerCase();
  for (const word of COMMON) {
    const all = await hashAll(word);
    for (const [alg, digest] of Object.entries(all)) if (digest === h) return { word, alg };
  }
  return null;
}

/* --------------------------------------------------------- password analysis */

function analyzePassword(pw) {
  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/[0-9]/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  let entropy = pw.length * Math.log2(pool || 1);

  const issues = [];
  const lower = pw.toLowerCase();
  const leet = lower.replace(/0/g, "o").replace(/1/g, "i").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/@/g, "a").replace(/\$/g, "s");
  if (COMMON.includes(lower) || COMMON.includes(leet)) { issues.push("in the top common-passwords list — cracked instantly"); entropy = Math.min(entropy, 5); }
  if (pw.length < 8) issues.push("shorter than 8 characters");
  if (/(.)\1{2,}/.test(pw)) { issues.push("repeated characters (aaa, 111)"); entropy *= 0.8; }
  if (/(abc|bcd|cde|123|234|345|456|567|678|789|qwe|wer|asd|zxc)/i.test(pw)) { issues.push("keyboard / alphabet sequence"); entropy *= 0.8; }
  if (/(19|20)\d{2}/.test(pw)) { issues.push("contains a year — easy to guess"); entropy *= 0.9; }
  if (/^[A-Z][a-z]+\d+[!@#$]?$/.test(pw)) { issues.push("predictable pattern: Word + numbers + symbol"); entropy *= 0.7; }
  if (pool && pool <= 26) issues.push("only one character type");

  const guesses = 2 ** entropy / 2;
  return {
    entropy,
    pool,
    offline: guesses / 1e11, // fast hash, GPU rig
    online: guesses / 100,   // rate-limited login form
    issues,
  };
}

function humanTime(sec) {
  if (sec < 1) return "instantly";
  const units = [["centuries", 3.15e9], ["years", 3.15e7], ["days", 86400], ["hours", 3600], ["minutes", 60], ["seconds", 1]];
  for (const [name, s] of units) {
    if (sec >= s) {
      const n = sec / s;
      if (name === "centuries" && n > 1e6) return "longer than the universe will exist";
      return `${n < 10 ? n.toFixed(1) : Math.round(n).toLocaleString()} ${name}`;
    }
  }
}

function passwordReport(pw) {
  if (!pw) return { text: "", pct: 0, color: "transparent" };
  const r = analyzePassword(pw);
  const pct = Math.min(100, (r.entropy / 100) * 100);
  const verdict = r.entropy < 28 ? ["VERY WEAK", "#ff3b5c"] : r.entropy < 45 ? ["WEAK", "#ff8c42"]
    : r.entropy < 65 ? ["OK", "#ffcc00"] : r.entropy < 85 ? ["STRONG", "#7dff9a"] : ["EXCELLENT", "#00ff66"];
  const text = [
    `verdict        : ${verdict[0]}`,
    `length         : ${pw.length}`,
    `charset size   : ${r.pool}`,
    `entropy        : ${r.entropy.toFixed(1)} bits`,
    `crack (offline): ${humanTime(r.offline)}   [100 billion guesses/s GPU]`,
    `crack (online) : ${humanTime(r.online)}   [100 guesses/s login form]`,
    "",
    r.issues.length ? "issues:\n" + r.issues.map((i) => "  [!] " + i).join("\n") : "no obvious weaknesses found ✓",
    "",
    "tip: a long passphrase like 'correct-horse-battery-staple' beats 'P@ssw0rd!'",
  ].join("\n");
  return { text, pct, color: verdict[1] };
}

$("pw").addEventListener("input", (e) => {
  const r = passwordReport(e.target.value);
  $("pw-report").textContent = r.text;
  $("pw-bar").style.width = r.pct + "%";
  $("pw-bar").style.background = r.color;
});

/* ------------------------------------------------------------------- hash UI */

$("hash-in").addEventListener("input", async (e) => {
  const all = await hashAll(e.target.value);
  $("hash-out").textContent = Object.entries(all).map(([k, v]) => `${k.padEnd(8)}: ${v}`).join("\n");
});

$("hashid-in").addEventListener("input", async (e) => {
  const v = e.target.value.trim();
  if (!v) { $("hashid-out").textContent = ""; return; }
  let text = "possible types:\n" + identifyHash(v).map((t) => "  → " + t).join("\n");
  $("hashid-out").textContent = text + "\n\nrunning dictionary attack on common passwords...";
  const hit = await crackHash(v);
  text += hit
    ? `\n\n[CRACKED] ${hit.alg}("${hit.word}")\nThis is why unsalted fast hashes are dangerous for passwords.`
    : "\n\nnot found in the built-in wordlist (that's good!)";
  $("hashid-out").textContent = text;
});

/* -------------------------------------------------------------------- ciphers */

function caesar(s, k) {
  k = ((k % 26) + 26) % 26;
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + k) % 26) + base);
  });
}

function vigenere(s, key, decrypt) {
  const ks = key.toLowerCase().replace(/[^a-z]/g, "");
  if (!ks) throw new Error("key must contain letters");
  let j = 0;
  return s.replace(/[a-z]/gi, (c) => {
    const k = ks.charCodeAt(j++ % ks.length) - 97;
    return caesar(c, decrypt ? -k : k);
  });
}

const ENGLISH = "etaoinshrdlcumwfgypbvkjxqz";
function englishScore(s) {
  const words = [" the ", " and ", " is ", " you ", " to ", " of ", " flag", "hello", " a "];
  let score = 0;
  for (const c of s.toLowerCase()) {
    const i = ENGLISH.indexOf(c);
    if (i >= 0) score += 26 - i;
  }
  for (const w of words) if ((" " + s.toLowerCase() + " ").includes(w)) score += 150;
  return score;
}

function bruteCaesar(s) {
  const results = [];
  for (let k = 1; k < 26; k++) {
    const t = caesar(s, -k);
    results.push({ k, t, score: englishScore(t) });
  }
  const best = results.reduce((a, b) => (b.score > a.score ? b : a));
  return results.map((r) => `${r === best ? ">>" : "  "} shift ${String(r.k).padStart(2)}: ${r.t}`).join("\n")
    + `\n\nmost likely: shift ${best.k} (scored by English letter frequency)`;
}

const MORSE = {
  a: ".-", b: "-...", c: "-.-.", d: "-..", e: ".", f: "..-.", g: "--.", h: "....", i: "..", j: ".---",
  k: "-.-", l: ".-..", m: "--", n: "-.", o: "---", p: ".--.", q: "--.-", r: ".-.", s: "...", t: "-",
  u: "..-", v: "...-", w: ".--", x: "-..-", y: "-.--", z: "--..", 0: "-----", 1: ".----", 2: "..---",
  3: "...--", 4: "....-", 5: ".....", 6: "-....", 7: "--...", 8: "---..", 9: "----.",
  ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--", "/": "-..-.", "@": ".--.-.",
};
const UNMORSE = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

const b64e = (s) => btoa(String.fromCharCode(...enc.encode(s)));
const b64d = (s) => dec.decode(Uint8Array.from(atob(s.trim().replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)));

function runCipher(mode, s, key) {
  switch (mode) {
    case "rot13": return caesar(s, 13);
    case "caesar": return caesar(s, parseInt(key, 10) || 0);
    case "brute": return bruteCaesar(s);
    case "vig-e": return vigenere(s, key, false);
    case "vig-d": return vigenere(s, key, true);
    case "b64-e": return b64e(s);
    case "b64-d": return b64d(s);
    case "hex-e": return toHex(enc.encode(s));
    case "hex-d": return dec.decode(Uint8Array.from(s.replace(/[^0-9a-f]/gi, "").match(/../g) || [], (h) => parseInt(h, 16)));
    case "bin-e": return [...enc.encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" ");
    case "bin-d": return dec.decode(Uint8Array.from(s.replace(/[^01]/g, "").match(/.{8}/g) || [], (b) => parseInt(b, 2)));
    case "morse-e": return [...s.toLowerCase()].map((c) => (c === " " ? "/" : MORSE[c] || "")).filter(Boolean).join(" ");
    case "morse-d": return s.trim().split(/\s+/).map((c) => (c === "/" ? " " : UNMORSE[c] || "?")).join("");
  }
}

$("ci-run").addEventListener("click", () => {
  try {
    $("ci-out").textContent = runCipher($("ci-mode").value, $("ci-in").value, $("ci-key").value);
  } catch (err) {
    $("ci-out").textContent = "error: " + err.message;
  }
});

/* ------------------------------------------------------------------------ JWT */

function auditJwt(token) {
  const parts = token.trim().split(".");
  if (parts.length !== 3) return "not a JWT — expected 3 dot-separated parts (header.payload.signature)";
  let header, payload;
  try {
    header = JSON.parse(b64d(parts[0]));
    payload = JSON.parse(b64d(parts[1]));
  } catch {
    return "could not decode header/payload as Base64URL JSON";
  }

  const findings = [];
  const alg = String(header.alg || "").toLowerCase();
  if (alg === "none") findings.push("[CRITICAL] alg is 'none' — the token is unsigned and can be forged by anyone");
  if (!parts[2]) findings.push("[CRITICAL] empty signature");
  if (alg.startsWith("hs")) findings.push("[INFO] HMAC-signed — security depends on a long, secret key (weak keys can be brute-forced)");
  if (payload.exp === undefined) findings.push("[WARN] no 'exp' claim — token never expires");
  else if (payload.exp * 1000 < Date.now()) findings.push(`[WARN] token EXPIRED at ${new Date(payload.exp * 1000).toISOString()}`);
  else findings.push(`[OK] expires ${new Date(payload.exp * 1000).toISOString()}`);
  for (const k of Object.keys(payload)) {
    if (/pass|secret|ssn|card/i.test(k)) findings.push(`[WARN] claim '${k}' looks sensitive — JWT payloads are only encoded, not encrypted`);
  }
  if (payload.admin === true || payload.role === "admin") findings.push("[INFO] privileged claim present — the server must verify the signature before trusting it");

  return [
    "HEADER:", JSON.stringify(header, null, 2), "",
    "PAYLOAD:", JSON.stringify(payload, null, 2), "",
    "AUDIT:", ...findings.map((f) => "  " + f),
  ].join("\n");
}

$("jwt-in").addEventListener("input", (e) => ($("jwt-out").textContent = auditJwt(e.target.value)));
$("jwt-out").textContent = auditJwt($("jwt-in").value);

/* ------------------------------------------------------------------- terminal */

const out = $("term-out");
const input = $("term-in");
const history = [];
let histIdx = 0;
let busy = false;

function print(text = "", cls = "") {
  const d = document.createElement("div");
  d.textContent = text;
  if (cls) d.className = cls;
  out.appendChild(d);
  $("terminal").scrollTop = $("terminal").scrollHeight;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function typeOut(lines, delay = 30) {
  for (const l of lines) { print(l); await sleep(delay); }
}

const TIPS = [
  "Use a password manager. You only need to remember one strong passphrase.",
  "Turn on 2FA everywhere — an app or hardware key beats SMS.",
  "Store passwords with bcrypt or Argon2, never plain MD5/SHA-1.",
  "Phishing is the #1 way accounts get hacked. Check the URL before you log in.",
  "Keep your OS and browser updated — most attacks use old, already-fixed bugs.",
  "Never trust input: validate on the server, not just in the browser.",
  "Parameterized queries stop SQL injection. String concatenation does not.",
  "Practice legally on CTFs: picoCTF, TryHackMe, Hack The Box, OverTheWire.",
];

const COMMANDS = {
  help: "show this help",
  whoami: "who are you?",
  sysinfo: "what your browser reveals about you",
  hack: "movie-style hacking simulation (100% fake)",
  pw: "pw <password> — analyze a password",
  hash: "hash <text> — hash text with MD5/SHA-*",
  hashid: "hashid <hash> — identify & try to crack a hash",
  rot13: "rot13 <text>",
  caesar: "caesar <text> — brute-force all shifts",
  b64: "b64 <text> — base64 encode",
  unb64: "unb64 <text> — base64 decode",
  jwt: "jwt <token> — decode & audit a JWT",
  tip: "random security tip",
  matrix: "toggle the matrix rain",
  open: "open <password|hash|cipher|jwt>",
  clear: "clear the screen",
};

async function run(line) {
  const [cmd, ...rest] = line.trim().split(/\s+/);
  const arg = line.trim().slice(cmd.length).trim();
  switch ((cmd || "").toLowerCase()) {
    case "": return;
    case "help":
      Object.entries(COMMANDS).forEach(([k, v]) => print(`  ${k.padEnd(8)} ${v}`));
      return;
    case "clear": out.innerHTML = ""; return;
    case "whoami": print("a future security engineer 😎"); return;
    case "tip": print("💡 " + TIPS[Math.floor(Math.random() * TIPS.length)]); return;
    case "matrix": matrixOn = !matrixOn; if (!matrixOn) ctx.clearRect(0, 0, canvas.width, canvas.height); print(`matrix rain ${matrixOn ? "on" : "off"}`); return;
    case "open":
      if (["password", "hash", "cipher", "jwt"].includes(rest[0])) openTab(rest[0]);
      else print("usage: open <password|hash|cipher|jwt>", "err");
      return;
    case "sysinfo":
      await typeOut([
        "every website you visit can see this:",
        `  user agent : ${navigator.userAgent}`,
        `  platform   : ${navigator.platform}`,
        `  language   : ${navigator.language}`,
        `  timezone   : ${Intl.DateTimeFormat().resolvedOptions().timeZone}`,
        `  screen     : ${screen.width}x${screen.height} @ ${devicePixelRatio}x`,
        `  cpu cores  : ${navigator.hardwareConcurrency || "?"}`,
        `  memory     : ${navigator.deviceMemory ? navigator.deviceMemory + " GB" : "hidden"}`,
        `  cookies    : ${navigator.cookieEnabled ? "enabled" : "disabled"}`,
        `  dnt        : ${navigator.doNotTrack === "1" ? "on" : "off"}`,
        "combined, these form a 'browser fingerprint' used for tracking.",
      ]);
      return;
    case "hack": {
      const target = rest[0] || "mainframe";
      print("[SIMULATION] nothing real is happening — this is movie magic ✨", "warn");
      await typeOut([
        `> connecting to ${target}...`,
        "> bypassing firewall ███████████ 100%",
        "> decrypting RSA-4096 key...",
        ...Array.from({ length: 8 }, () => "  " + Array.from({ length: 6 }, () => Math.random().toString(16).slice(2, 10)).join(" ")),
        "> injecting payload into kernel...",
        "> downloading more RAM...",
        "> enhance... ENHANCE...",
      ], 180);
      await sleep(400);
      print("ACCESS GRANTED", "warn");
      print("(real hacking is mostly reading docs and asking permission — try `tip`)");
      return;
    }
    case "pw":
      if (!arg) return print("usage: pw <password>", "err");
      passwordReport(arg).text.split("\n").forEach((l) => print(l));
      return;
    case "hash":
      Object.entries(await hashAll(arg)).forEach(([k, v]) => print(`${k.padEnd(8)}: ${v}`));
      return;
    case "hashid": {
      if (!arg) return print("usage: hashid <hash>", "err");
      identifyHash(arg).forEach((t) => print("  → " + t));
      print("running dictionary attack...");
      const hit = await crackHash(arg);
      print(hit ? `[CRACKED] ${hit.alg}("${hit.word}")` : "not in wordlist", hit ? "warn" : "");
      return;
    }
    case "rot13": print(caesar(arg, 13)); return;
    case "caesar": bruteCaesar(arg).split("\n").forEach((l) => print(l)); return;
    case "b64": print(b64e(arg)); return;
    case "unb64":
      try { print(b64d(arg)); } catch { print("invalid base64", "err"); }
      return;
    case "jwt": auditJwt(arg).split("\n").forEach((l) => print(l)); return;
    case "sudo": print("nice try. this incident will be reported. 🚨", "err"); return;
    case "rm": print("whoa there. no.", "err"); return;
    case "exit": print("there is no escape from the matrix.", "warn"); return;
    default: print(`command not found: ${cmd} — type 'help'`, "err");
  }
}

input.addEventListener("keydown", async (e) => {
  if (e.key === "Enter" && !busy) {
    const line = input.value;
    input.value = "";
    print("root@cyberkit:~$ " + line, "prompt");
    if (line.trim()) { history.push(line); histIdx = history.length; }
    busy = true;
    try { await run(line); } catch (err) { print("error: " + err.message, "err"); }
    busy = false;
  } else if (e.key === "ArrowUp" && histIdx > 0) {
    input.value = history[--histIdx];
    e.preventDefault();
  } else if (e.key === "ArrowDown") {
    histIdx = Math.min(history.length, histIdx + 1);
    input.value = history[histIdx] || "";
  }
});

$("terminal").addEventListener("click", () => input.focus());

typeOut([
  "CyberKit v1.0 — booting...",
  "[ok] crypto engine loaded",
  "[ok] cipher lab online",
  "[ok] password analyzer armed",
  "",
  "type 'help' to see commands. try: hack, sysinfo, pw hunter2, hashid 5f4dcc3b5aa765d61d8327deb882cf99",
], 120).then(() => input.focus());
