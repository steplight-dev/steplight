// Regenerates the shared contract files in spec/ from the TypeScript implementation, so every SDK
// (TypeScript, Python, ...) can be tested against exactly what the reference engine does:
//
//   spec/redaction-vectors.json   input -> expected output cases for the redaction engine
//   spec/never-capture.json       the always-on "never capture" rules, as data
//   spec/page-scan.js             the standalone in-page script (scan, clicks, inputs, submits)
//
// It reads the BUILT packages, so run `pnpm -r build` first, then `pnpm spec`. The Python package keeps
// copies of the two files it needs at run time in python/src/steplight/_data/ (written here too).
// Pass --check to compare instead of write (exit 1 when a file is out of date).
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const core = await import(pathToFileURL(path.join(root, "packages/core/dist/index.js")).href);
const sdk = await import(pathToFileURL(path.join(root, "packages/sdk/dist/pageScript.js")).href);
const check = process.argv.includes("--check");

const stale = [];
async function emit(file, text) {
  const target = path.join(root, file);
  if (check) {
    const current = await readFile(target, "utf8").catch(() => "");
    if (current !== text) stale.push(file);
    return;
  }
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, text);
}

/* ------------------------------------------------------------------ never-capture.json */

const probe = (descriptor) => ({ descriptor, neverCapture: core.isNeverCaptureField(descriptor) });
const neverCases = [
  { tag: "input", type: "password" },
  { tag: "input", type: "PASSWORD" },
  { tag: "input", type: "text", name: "email" },
  { tag: "input", type: "email", name: "email", autocomplete: "email" },
  { tag: "input", name: "cardNumber" },
  { tag: "input", name: "card_number" },
  { tag: "input", name: "cc-number" },
  { tag: "input", name: "ccnum" },
  { tag: "input", name: "creditcard" },
  { tag: "input", name: "cvv" },
  { tag: "input", name: "cvc2" },
  { tag: "input", name: "csc" },
  { tag: "input", id: "otp" },
  { tag: "input", id: "OTP-code" },
  { tag: "input", name: "userPin" },
  { tag: "input", name: "pin_code" },
  { tag: "input", name: "pinterest" },
  { tag: "input", name: "shipping" },
  { tag: "input", name: "ssn" },
  { tag: "input", name: "aadhaar" },
  { tag: "input", name: "aadhaarNo" },
  { tag: "input", name: "pan" },
  { tag: "input", name: "panno" },
  { tag: "input", name: "company" },
  { tag: "input", name: "passcode" },
  { tag: "input", name: "passwd" },
  { tag: "input", name: "iban" },
  { tag: "input", name: "secret" },
  { tag: "input", name: "csrf_token" },
  { tag: "input", name: "csrfToken" },
  { tag: "input", name: "token" },
  { tag: "input", name: "tokenizer" },
  { tag: "input", name: "q", autocomplete: "cc-number" },
  { tag: "input", name: "q", autocomplete: "cc-exp" },
  { tag: "input", name: "q", autocomplete: "one-time-code" },
  { tag: "input", name: "q", autocomplete: "current-password" },
  { tag: "input", name: "q", autocomplete: "new-password" },
  { tag: "input", name: "q", autocomplete: "username" },
  { tag: "input", name: "q", autocomplete: "name email cc-csc" },
  { tag: "input", name: "q", ariaLabel: "Card number" },
  { tag: "input", name: "q", ariaLabel: "Search" },
  { tag: "input", name: "q", placeholder: "Enter your PIN" },
  { tag: "input", name: "q", label: "Security code (CVV)" },
  { tag: "textarea", name: "cardnote" },
  { tag: "textarea", name: "notes" },
  { tag: "select", name: "card" },
  { tag: "div", contentEditable: true, ariaLabel: "CVV" },
  { tag: "div", contentEditable: true, ariaLabel: "Comment" },
  { tag: "input", name: "q", inPaymentFrame: true },
  { tag: "div", contentEditable: true, inPaymentFrame: true },
  { tag: "div", inPaymentFrame: true },
  { tag: "button", name: "card", inPaymentFrame: true },
  { tag: "input" },
  {},
].map(probe);

const urlCases = [
  "https://js.stripe.com/v3/",
  "https://checkout.stripe.com/pay",
  "https://www.paypal.com/checkoutnow",
  "https://notstripe.com/",
  "https://stripe.com.evil.example/",
  "https://example.com/stripe.com",
  "https://pay.razorpay.com/x",
  "https://api.payu.in/",
  "http://localhost:3000/",
  "not a url",
  "",
].map((url) => ({ url, paymentFrame: core.isPaymentFrameUrl(url) }));

await emit(
  "spec/never-capture.json",
  JSON.stringify(
    {
      formatVersion: 1,
      description:
        "Fields whose contents Steplight never reads, whatever the capture level or settings. Generated from packages/core/src/neverCapture.ts by `pnpm spec`. An SDK must apply these rules (the shared page script already does, in the browser) and pass every case below. Patterns are JavaScript regular expressions; `splitCamelCase` is applied to name, id, aria-label, placeholder and label before `namePattern` is tested against their space-joined text.",
      inputTypes: ["password"],
      autocompletePattern: { source: core.NEVER_CAPTURE_AUTOCOMPLETE.source, flags: core.NEVER_CAPTURE_AUTOCOMPLETE.flags },
      namePattern: { source: core.NEVER_CAPTURE_NAME_PATTERN.source, flags: core.NEVER_CAPTURE_NAME_PATTERN.flags },
      splitCamelCase: { source: "([a-z0-9])([A-Z])", flags: "g", replacement: "$1_$2" },
      editableTags: ["input", "textarea", "select"],
      paymentFrameHosts: [...core.PAYMENT_FRAME_HOSTS],
      fieldCases: neverCases,
      urlCases,
    },
    null,
    2,
  ) + "\n",
);

/* ------------------------------------------------------------------ redaction-vectors.json */

let seed = 20261009;
const rand = () => {
  // mulberry32: deterministic, so regenerating gives the same file
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const pick = (list) => list[Math.floor(rand() * list.length)];
const digits = (n) => Array.from({ length: n }, () => Math.floor(rand() * 10)).join("");
const alnum = (n, set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") => Array.from({ length: n }, () => pick([...set])).join("");

const cases = [];
const add = (group, input, note) => {
  const redacted = core.redactText(input);
  const again = core.redactText(redacted);
  const kinds = (credentials) => core.findSensitive(input, { credentials }).map((m) => m.kind);
  const c = { id: `${group}-${String(cases.filter((x) => x.group === group).length + 1).padStart(3, "0")}`, group, input, redact: redacted, idempotent: again === redacted, find: kinds(false), findCredentials: kinds(true) };
  if (note) c.note = note;
  cases.push(c);
};
/** A large input written compactly: {repeat: [unit, times], prefix?, suffix?}. */
const addRepeat = (group, unit, times, prefix = "", suffix = "", note) => {
  const input = prefix + unit.repeat(times) + suffix;
  add(group, input, note);
  const last = cases[cases.length - 1];
  last.input = { repeat: [unit, times], ...(prefix ? { prefix } : {}), ...(suffix ? { suffix } : {}) };
  return last;
};

// --- emails
for (const e of [
  "jane@example.com", "Jane.Doe@Example.COM", "a+tag@sub.domain.example.org", "first_last-1@my-site.co.uk", "x@y.io", "user%2Btag@example.com",
  "UPPER@LOWER.NET", "a.b.c.d@e.f.g.h.example.travel", "me@localhost.localdomain.example", "someone@example.technology",
]) {
  add("email", e);
  add("email", `Contact: ${e}.`, "end of sentence");
  add("email", `<${e}>`, "angle brackets");
}
add("email", "mailto:support@example.com?subject=Hi");
add("email", "two a@b.co and c@d.org in one line");
add("email", "a@b.co,c@d.org;e@f.net");
add("email", "no tld: user@localhost");
add("email", "one-letter tld: a@b.c");
add("email", "handle @someone only");
add("email", "@ alone and a@ alone");
add("email", `${"x".repeat(70)}@example.com`, "local part longer than 64");
add("email", "dots..in..local@example.com");
add("email", "trailing dot in domain: a@example.com.");
add("email", "unicode local: jürgen@example.com");
add("email", "unicode domain: a@exämple.com");
add("email", "url query: https://x.test/?email=a%40b.co&x=1");
add("email", "form body: email=traveler%40example.com&flight=AI-101");
add("email", "double encoded: a%2540b.co");
add("email", "triple encoded: a%252540b.co");
add("email", "json escape: \"a\\u0040b.co\"");
add("email", "html entity: a&#64;b.co");
add("email", "html hex entity: a&#x40;b.co");
add("email", "slash-escaped json: \"a@b.co\\/path\"");
add("email", "emoji next to it 😀jane@example.com😀");
add("email", "glued: IDjane@example.comEND");
add("email", "tab\tjane@example.com\nnewline");

// --- cards
const luhnComplete = (prefix, length) => {
  const body = prefix + digits(length - 1 - prefix.length);
  for (let d = 0; d < 10; d++) if (core.luhnValid(body + d)) return body + d;
  throw new Error("no luhn digit");
};
const brands = [
  ["visa", "4", 16], ["visa13", "4", 13], ["mastercard", "51", 16], ["mastercard2", "2221", 16], ["amex", "34", 15], ["amex2", "37", 15],
  ["discover", "6011", 16], ["diners", "36", 14], ["jcb", "3528", 16], ["unionpay", "62", 19], ["maestro", "5018", 16], ["rupay", "6521", 16],
];
for (const [, prefix, len] of brands) {
  const n = luhnComplete(prefix, len);
  add("card", n);
  add("card", n.replace(/(\d{4})(?=\d)/g, "$1 "), "grouped with spaces");
  add("card", n.replace(/(\d{4})(?=\d)/g, "$1-"), "grouped with dashes");
  add("card", `Paying with card ${n}, thanks`, "in a sentence");
}
add("card", "4242 4242 4242 4242");
add("card", "4111-1111-1111-1111");
add("card", "5555555555554444");
add("card", "378282246310005");
add("card", "4242 4242 4242 4241", "fails Luhn");
add("card", "1234 5678 9012 3456", "fails Luhn");
add("card", "4242 4242 4242", "twelve digits");
add("card", "42424242424242424242", "twenty digits");
add("card", "order 12345 4242 4242 4242 4242 shipped", "card next to another number");
add("card", "4242 4242 4242 4242 4242 4242", "two cards back to back");
add("card", "4242 4242 4242 4242 and 5555 5555 5555 4444", "two cards");
add("card", "4242_4242_4242_4242", "underscores are not separators");
add("card", "4242  4242  4242  4242", "double spaces are not separators");
add("card", "4242 4242-4242 4242", "mixed single separators");
add("card", "card:4242424242424242;", "punctuation around");
add("card", "%34242 4242 4242 4242", "percent-encoded first digit");
add("card", "4242%204242%204242%204242", "percent-encoded spaces");

// --- API keys and tokens
const keyBody = (n) => alnum(n);
const apiKeys = [
  `sk-${keyBody(48)}`, `sk-proj-${keyBody(40)}`, `sk-ant-api03-${alnum(60, "abcdefghijklmnopqrstuvwxyz0123456789_-")}`, `sk-ant-${keyBody(30)}`,
  `AKIA${alnum(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`, `ASIA${alnum(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`,
  `AROA${alnum(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")}`, `ghp_${keyBody(36)}`, `gho_${keyBody(36)}`, `ghs_${keyBody(36)}`,
  `github_pat_${alnum(70, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")}`, `xoxb-${digits(12)}-${digits(12)}-${keyBody(24)}`,
  `xoxp-${digits(10)}-${keyBody(20)}`, `xapp-1-${keyBody(24)}`, `sk_live_${keyBody(32)}`, `sk_test_${keyBody(32)}`, `rk_live_${keyBody(24)}`,
  `whsec_${keyBody(32)}`, `AIza${alnum(35, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")}`, `npm_${keyBody(36)}`,
];
for (const k of apiKeys) {
  add("api_key", k);
  add("api_key", `Authorization key is ${k} - keep it safe`, "in a sentence");
  add("api_key", `{"key":"${k}"}`, "in JSON");
}
add("api_key", "sk-short", "too short");
add("api_key", "task-force-ready-to-go-now", "contains 'sk-' inside a word");
add("api_key", "ghp_tooshort", "too short");
add("api_key", "AKIA1234", "too short");
add("api_key", "prefix-sk" + "-abcdefghijklmnopqrstuvwxyz", "preceded by a word character");
add("api_key", "AKIA" + "IOSFODNN7EXAMPLE");
add("api_key", "ghp_" + "a".repeat(30));

// --- JWT, private keys, bearer / basic
const b64u = (s) => Buffer.from(s).toString("base64url");
const jwt = `${b64u('{"alg":"HS256","typ":"JWT"}')}.${b64u('{"sub":"1234567890","name":"Jane"}')}.${alnum(43, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")}`;
add("jwt", jwt);
add("jwt", `Bearer ${jwt}`, "bearer wins or jwt wins: whichever the engine picks");
add("jwt", `token=${jwt}&x=1`);
add("jwt", `cookie: session=${jwt}; Path=/`);
add("jwt", "eyJhbGciOi.eyJzdWIi.sig", "too short");
add("jwt", `${jwt.split(".")[0]}.${jwt.split(".")[1]}`, "two segments only");
for (const kind of ["RSA PRIVATE KEY", "PRIVATE KEY", "EC PRIVATE KEY", "OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]) {
  add("private_key", `-----BEGIN ${kind}-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nabcdef==\n-----END ${kind}-----`);
  add("private_key", `before\n-----BEGIN ${kind}-----\nQUJD\n-----END ${kind}-----\nafter`, "with text around");
}
add("private_key", "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0B", "unterminated: redacts to the end (fail closed)");
add("private_key", "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n-----END CERTIFICATE-----", "a certificate is public");
add("private_key", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBg\n-----END PUBLIC KEY-----");
add("private_key", "-----BEGIN " + "PRIVATE KEY----- two keys -----BEGIN " + "PRIVATE KEY-----\nQQ\n-----END PRIVATE KEY-----");
add("private_key", "-----BEGIN ", "truncated header");
for (const c of [
  "Bearer abcdefghijklmnop1234", "bearer ABCDEFGHIJKLMNOP.qrstuv-wxyz_1234", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz", "Basic dXNlcjpwYXNzd29yZDEyMzQ=",
  "basic YWxhZGRpbjpvcGVuc2VzYW1l", "Bearer short", "Bearer  twospacesabcdefghijklmnop", "Authorization: Basic Zm9vOmJhcg==", "the bearer of this letter is welcome",
]) add("bearer", c);

// --- password pairs and URL parameters
for (const c of [
  "password=hunter2xyz", "password: hunter2xyz", 'password":"hunter2xyz"', '"password": "hunter2xyz"', "passwd=abcdef", "pwd=abcdef", "passphrase=correcthorse",
  "secret=abcd1234", "api_key=abcd1234efgh", "api-key: abcd1234efgh", "apikey=abcd1234efgh", "access_token=abcdefgh12345678", "auth_token: abcdefgh12345678",
  "refresh_token=abcdefgh12345678", "client_secret=abcdefgh12345678", "private_key=abcdefgh12345678", "credentials=abcdef", "PASSWORD=HUNTER2",
  "Password = hunter2xyz", "pass=ab", "password=", "password is hunter2xyz", "mypassword=hunter2xyz", "email=a@b.co&password=hunter2xyz&remember=1",
  "user=bob; password=hunter2xyz; path=/", "password='single quoted'", "secrets=abc123", "new_password=hunter2xyz", "pw=hunter2xyz",
]) add("password", c);
for (const c of [
  "https://x.test/cb?token=abcdef123456", "https://x.test/cb?access_token=abc123&x=1", "https://x.test/?key=abcdef", "https://x.test/?code=ZXCVB", "https://x.test/?session=abc123",
  "https://x.test/?sessionid=abc123", "https://x.test/?sid=abc123", "https://x.test/?auth=abc123", "https://x.test/?authorization=abc123", "https://x.test/?sig=abc123",
  "https://x.test/?otp=123456", "https://x.test/?jwt=abc.def.ghi", "https://x.test/?password=abc123&q=1", "https://x.test/?apikey=abc123", "https://x.test/?api_key=abc123",
  "https://x.test/?x_secret=abc123", "https://x.test/?userToken=abc123", "https://x.test/?signature=abc123", "https://x.test/?a=1&token=abc123&b=2", "https://x.test/?a=1;token=abc123",
  "https://x.test/#token=abc123", "https://x.test/?q=keyboard", "https://x.test/?monkey=abc", "https://x.test/?tokenless=1", "token=abc123 at the start", "code=ZXCVB in text",
  "?key=abc&code=def", "https://x.test/?token=", "https://x.test/?Token=ABC123",
]) add("url_param", c);

// --- IBAN
const ibans = [
  ["GB", "WEST12345698765432"], ["DE", "370400440532013000"], ["FR", "20041010050500013M02606"], ["ES", "21000418450200051332"], ["IT", "X0542811101000000123456"],
  ["NL", "ABNA0417164300"], ["BE", "539007547034"], ["CH", "0483501234567890"], ["AT", "1904300234573201"], ["PL", "109024020280000000000000"], ["SE", "5000000000053849475"],
  ["NO", "86011117947"], ["IE", "AIBK93115212345678"], ["PT", "00020123123456789015"], ["DK", "00400440116243"], ["FI", "21234600000785"],
];
for (const [cc, bban] of ibans) {
  const iban = `${cc}${core.ibanCheckDigits(cc, bban)}${bban}`;
  add("iban", iban);
  add("iban", iban.replace(/(.{4})/g, "$1 ").trim(), "grouped in fours");
  add("iban", `IBAN: ${iban} (main account)`, "in a sentence");
  const good = Number(core.ibanCheckDigits(cc, bban));
  const wrong = `${cc}${String(((good - 1) % 96) + 2).padStart(2, "0")}${bban}`;
  add("iban", wrong, "bad check digits");
}
add("iban", "GB82 WEST 1234 5698 7654 32");
add("iban", "gb82west12345698765432", "lowercase is not matched");
add("iban", "XX00 0000 0000 0000", "no valid structure");
add("iban", "GB82WEST12345698765432X", "extra trailing letter");
add("iban", "AGB82WEST12345698765432", "extra leading letter");

// --- SSN
for (const c of [
  "123-45-6789", "SSN 078-05-1120 on file", "000-12-3456", "666-12-3456", "900-12-3456", "123-00-6789", "123-45-0000", "123456789", "123-456-789", "1234-56-7890", "x123-45-6789",
  "123-45-67890", "My number is 219-09-9999.",
]) add("ssn", c);

// --- Aadhaar
const aadhaar = (n) => core.verhoeffAppend(n);
for (let i = 0; i < 6; i++) {
  const a = aadhaar(String(2 + Math.floor(rand() * 8)) + digits(10));
  add("aadhaar", a.replace(/(\d{4})(\d{4})(\d{4})/, "$1 $2 $3"), "grouped, valid check digit");
  add("aadhaar", a.replace(/(\d{4})(\d{4})(\d{4})/, "$1-$2-$3"), "grouped with dashes");
  add("aadhaar", `Aadhaar: ${a}`, "plain with the word nearby");
  add("aadhaar", `reference ${a} for order`, "plain, no context: not treated as Aadhaar");
  add("aadhaar", `UID ${a}`, "plain with UID");
}
add("aadhaar", "2345 6789 0124", "grouped, probably invalid check digit");
add("aadhaar", "1234 5678 9012", "starts with 1: not Aadhaar");
add("aadhaar", "Aadhaar number 234567890124", "plain, invalid check digit");

// --- PAN
for (const c of ["ABCPE1234F", "PAN: ABCDE1234F", "abcpe1234f", "ABCXE1234F", "ABCPE12345", "XABCPE1234F", "ABCPE1234FX", "AAAPL1234C", "ABCTE1234Z"]) add("pan", c);

// --- phone numbers
for (const c of [
  "+91 98765 43210", "+919876543210", "98765 43210", "9876543210", "09876543210", "919876543210", "+1 415-555-2671", "(415) 555-2671", "415-555-2671", "415.555.2671",
  "+44 20 7946 0958", "+49 30 901820", "+33 1 23 45 67 89", "call 555-1234 now", "order 98765 43210 shipped", "total 1,499 98765 43210", "1234567", "12345678", "+1234567",
  "2026-10-08", "10/08/2026", "v1.2.3.4567", "192.168.100.200", "amount: 1,499.00", "8765432109 is not indian mobile? (starts with 8)", "5876543210",
  "0044 20 7946 0958", "tel:+91-98765-43210", "x+919876543210", "a@b.co 9876543210",
]) add("phone", c);

// --- base64 / encoded
const enc = (s) => Buffer.from(s).toString("base64");
for (const secret of ["jane@example.com", "card 4242 4242 4242 4242", `key ${apiKeys[0]}`, "email=traveler@example.com&x=1", "password=hunter2xyz", "contact: a.b@c.org please"]) {
  add("encoded", enc(secret));
  add("encoded", `data=${enc(secret)}`, "as a parameter");
  add("encoded", Buffer.from(secret).toString("base64url"), "url-safe alphabet");
}
add("encoded", enc("just some harmless text that is long enough"), "decodes to harmless text");
add("encoded", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnop", "a long word, not base64");
add("encoded", "QWxsIHdvcmsgYW5kIG5vIHBsYXkgbWFrZXMgSmFjayBhIGR1bGwgYm95", "base64 of a harmless sentence");
add("encoded", enc("jane@example.com").replace(/=+$/, ""), "padding removed");
add("encoded", `${enc("jane@example.com")}==extra`, "garbage after padding");
add("encoded", enc(enc("jane@example.com")), "double encoded: the engine decodes one layer");

// --- clean text (must not change)
for (const c of [
  "", " ", "hello world", "The quick brown fox jumps over the lazy dog.", "Price: ₹28,000 for Economy · 2h 10m", "Flights: Delhi → Mumbai", "<div class=\"a\">text</div>",
  "SELECT * FROM users WHERE id = 42;", "2026-10-08T10:15:00Z", "https://example.com/path/to/page?x=1&y=2", "item #12345 qty 3", "v1.2.3", "tel: none", "email us",
  "user @ home", "a @ b . co", "日本語のテキスト", "Привет, мир", "مرحبا بالعالم", "emoji 😀 text 👍", "line1\nline2\r\nline3", "tab\tseparated\tvalues", "0123456789",
  "ID 4242", "12 34 56", "x".repeat(100),
]) add("clean", c);

// --- escapes decoded in the output when something was found
add("escape", "mail%20me:%20a%40b.co%20now");
add("escape", "mail%20me: nothing sensitive here", "no finding: input returned unchanged, escapes kept");
add("escape", "caf%C3%A9 a%40b.co", "multi-byte percent escape");
add("escape", "bad %ZZ escape a%40b.co");
add("escape", "bad utf8 %C3%28 a%40b.co", "invalid UTF-8 sequence stays encoded");
add("escape", "\\u0061\\u0040b.co", "all characters escaped");
add("escape", "key\\u003Dsk-" + "a".repeat(24), "escaped equals sign");
add("escape", "&#97;&#64;b.co");
add("escape", "&#x61;&#x40;b.co");
add("escape", "&#0;a@b.co", "entity for NUL stays");
add("escape", "&#55357;a@b.co", "surrogate entity stays");
add("escape", "https:\\/\\/x.test\\/?token=abc123");

// --- mixed documents
add("mixed", "email=a@b.co&card=4242 4242 4242 4242&password=hunter2xyz");
add("mixed", `{"user":"jane@example.com","key":"${apiKeys[0]}","card":"4242424242424242","phone":"+91 98765 43210"}`);
add("mixed", `Dear Jane (jane@example.com),\nYour order 55555 is confirmed. Card ending 4242 charged.\nSupport: +1 415-555-2671\nIBAN: GB82 WEST 1234 5698 7654 32`);
add("mixed", `GET /api?token=abc123&email=a%40b.co HTTP/1.1\nAuthorization: Bearer abcdefghijklmnop1234\nCookie: session=xyz`);
add("mixed", `<input name="email" value="a@b.co"><input name="cc" value="4242 4242 4242 4242">`);
add("mixed", `${jwt} ${apiKeys[1]} a@b.co`);
add("mixed", "a@b.co a@b.co a@b.co a@b.co");
add("mixed", "[REDACTED:email] already redacted, then c@d.org");
add("mixed", "x@y.zz4242 4242 4242 4242");
add("mixed", "4242 4242 4242 4242@example.com", "card digits inside an email-like token");
add("mixed", "password=a@b.co", "an email inside a password value: the earlier match wins");
add("mixed", "https://x.test/?token=sk-" + "a".repeat(30), "key inside a token parameter");
add("mixed", "token=4242 4242 4242 4242", "card after a parameter");

// --- idempotency: redacted output fed back in
for (const c of [
  "[REDACTED:email]", "[REDACTED:card] and [REDACTED:api_key]", "x [REDACTED:password] y", "[REDACTED:email][REDACTED:email]", "[REDACTED:error]", "[REDACTED:unknown_kind]",
  "email=[REDACTED:email]&card=[REDACTED:card]", "[REDACTED:phone] 9876543210",
]) add("idempotent", c);
for (let i = 0; i < 12; i++) add("idempotent", core.redactText(String(pick(cases).input)), "redacted output of another case, redacted again");

// --- hostile inputs (linear time; small enough to keep the file readable)
addRepeat("hostile", "a@", 600, "", "!", "many at-signs");
addRepeat("hostile", "1 ", 900, "", "x", "digit groups");
addRepeat("hostile", "1-", 900, "", "x", "digit groups with dashes");
addRepeat("hostile", "4242 ", 300, "", "", "card-like groups, no Luhn alignment");
addRepeat("hostile", "eyJ", 400, "", "", "many JWT starts");
addRepeat("hostile", "sk-", 400, "", "", "many key prefixes");
addRepeat("hostile", "-----BEGIN ", 200, "", "", "many PEM starts");
addRepeat("hostile", "password=", 300, "", "", "many empty password pairs");
addRepeat("hostile", "token=a&", 300, "", "", "many short parameters");
addRepeat("hostile", "a", 3000, "", "@example.com", "very long local part");
addRepeat("hostile", "a.", 500, "x@", "com", "very long domain");
addRepeat("hostile", "+1 ", 400, "", "", "many plus signs");
addRepeat("hostile", "(1)", 400, "", "", "many parentheses");
addRepeat("hostile", "A", 2000, "", "", "one long base64-looking word");
addRepeat("hostile", "QUJD", 600, "", "", "long valid base64 of harmless text");
addRepeat("hostile", "Bearer ", 300, "", "", "many bearer words");
addRepeat("hostile", "\\u0040", 400, "a", "b.co", "many escapes");
addRepeat("hostile", "%40", 400, "a", "b.co", "many percent escapes");
addRepeat("hostile", "&#64;", 400, "a", "b.co", "many entities");
addRepeat("hostile", "%25", 300, "a", "40b.co", "deep percent nesting");
addRepeat("hostile", "[REDACTED:email]", 200, "", "", "many markers");
addRepeat("hostile", "1234 5678 9012 ", 150, "", "", "many aadhaar-like groups");
addRepeat("hostile", "ABCPE1234F", 200, "", "", "many PANs glued together");
addRepeat("hostile", "GB82WEST12345698765432", 100, "", "", "many IBANs glued together");
addRepeat("hostile", "\n", 3000, "a@b.co", "", "many newlines");
addRepeat("hostile", " ", 5000, "password=", "x", "password pair with huge gap");

// --- size limits: sanitizeBody keeps 2048 characters, sanitizeSnapshot 204800
const sanitize = [];
const addSanitize = (kind, input, note) => {
  const out = kind === "body" ? core.sanitizeBody(input) : core.sanitizeSnapshot(input);
  const id = `sanitize-${kind}-${String(sanitize.filter((x) => x.kind === kind).length + 1).padStart(3, "0")}`;
  // Big outputs are stored as a digest (UTF-16 length + SHA-256 of the UTF-8 text) to keep the file small.
  const c = out.length > 4000 ? { id, kind, input, outputDigest: { length: out.length, sha256: createHash("sha256").update(out, "utf8").digest("hex") } } : { id, kind, input, output: out };
  if (note) c.note = note;
  sanitize.push(c);
  return c;
};
const addSanitizeRepeat = (kind, unit, times, prefix = "", suffix = "", note) => {
  const c = addSanitize(kind, prefix + unit.repeat(times) + suffix, note);
  c.input = { repeat: [unit, times], ...(prefix ? { prefix } : {}), ...(suffix ? { suffix } : {}) };
};
addSanitize("body", "email=a%40b.co&x=1");
addSanitize("body", "short body without secrets");
addSanitizeRepeat("body", "x", 2048, "", "", "exactly at the limit");
addSanitizeRepeat("body", "x", 2049, "", "", "one over the limit");
addSanitizeRepeat("body", "word ", 1000, "a@b.co ", "", "email before the cut");
addSanitizeRepeat("body", "word ", 500, "", " a@b.co tail ".repeat(200), "emails after the cut are dropped with the tail");
addSanitizeRepeat("body", "é", 3000, "", "", "two-byte characters count one each");
addSanitizeRepeat("body", "x", 2040, "k=", "&password=hunter2xyz", "secret straddles the cut");
addSanitizeRepeat("snapshot", "line of page text\n", 20, "Contact a@b.co\n");
addSanitizeRepeat("snapshot", "x", 204800, "", "", "exactly at the limit");
addSanitizeRepeat("snapshot", "x", 204801, "", "", "one over the limit");
addSanitizeRepeat("snapshot", "Hello world and more words. ", 8000, "start a@b.co\n", "\nend c@d.org", "a large page");
addSanitize("snapshot", "emoji 😀 and a@b.co and 𝒳 math");
addSanitizeRepeat("snapshot", "😀", 110000, "", "", "astral characters count two units each, so the cut is at 102400 of them");

// --- secret-shaped text is never stored literally. GitHub push protection and gitleaks flag anything that
// looks like a provider key, even a fake one in a test file, so every string that matches one of these
// formats is written as {join: [part, part, ...]} (split after four characters, so no part matches on its
// own) and the test loaders join the parts back at run time.
const SECRET_SHAPES = [
  /xox[baprs]-[0-9A-Za-z-]{10,}|xapp-\d-[0-9A-Za-z-]{10,}/g, // Slack
  /hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9/+]{20,}/g,
  /\b[sr]k_(?:live|test)_[0-9a-zA-Z]{10,}|\bpk_(?:live|test)_[0-9a-zA-Z]{10,}|whsec_[0-9a-zA-Z]{16,}/g, // Stripe
  /\b(?:AKIA|ASIA|AROA|AIDA|AGPA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/g, // AWS
  /\bgh[pousr]_[0-9A-Za-z]{30,}|github_pat_[0-9A-Za-z_]{40,}/g, // GitHub
  /\bsk-(?:proj-|svcacct-|admin-|ant-)?[0-9A-Za-z_-]{20,}/g, // OpenAI, Anthropic
  /AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]{20,}/g, // Google
  /\bnpm_[0-9A-Za-z]{30,}/g, // npm
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/g, // PEM
  /\beyJ[0-9A-Za-z_-]{8,}\.eyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}/g, // JWT
  /glpat-[0-9A-Za-z_-]{20,}|\bhf_[0-9A-Za-z]{30,}|\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}/g,
];
const encodeSecrets = (text) => {
  if (typeof text !== "string") return text;
  const cuts = new Set();
  for (const rx of SECRET_SHAPES) for (const m of text.matchAll(rx)) cuts.add(m.index + 4);
  if (cuts.size === 0) return text;
  const parts = [];
  let last = 0;
  for (const at of [...cuts].sort((a, b) => a - b)) {
    parts.push(text.slice(last, at));
    last = at;
  }
  parts.push(text.slice(last));
  const join = parts.filter((p) => p !== "");
  if (join.join("") !== text) throw new Error("secret encoding is not lossless");
  for (const part of join) for (const rx of SECRET_SHAPES) if (new RegExp(rx.source).test(part)) throw new Error(`a part still looks like a secret: ${part.slice(0, 12)}`);
  return { join };
};
for (const c of cases) {
  c.input = encodeSecrets(c.input);
  c.redact = encodeSecrets(c.redact);
}
for (const c of sanitize) {
  c.input = encodeSecrets(c.input);
  if (c.output !== undefined) c.output = encodeSecrets(c.output);
}

const groups = {};
for (const c of cases) groups[c.group] = (groups[c.group] ?? 0) + 1;
const total = cases.length + sanitize.length;
if (total < 300) throw new Error(`expected 300+ vectors, generated ${total}`);
// Redacting twice must change nothing - except for hostile inputs longer than a scanner's length cap, where a second pass may redact what the cap left behind.
for (const c of cases) if (!c.idempotent && c.group !== "hostile") throw new Error(`not idempotent: ${c.id}`);

await emit(
  "spec/redaction-vectors.json",
  JSON.stringify(
    {
      formatVersion: 1,
      description:
        "Input -> expected output cases generated from the TypeScript redaction engine (packages/core/src/redact.ts) by `pnpm spec`. `redact` is redactText(input); `find` / `findCredentials` are the kinds findSensitive reports without / with credentials; `idempotent` says redact(redact(x)) == redact(x). `sanitize` cases check sanitizeBody (2048 UTF-16 units) and sanitizeSnapshot (204800); a long output is given as `outputDigest` (length in UTF-16 units and SHA-256 of the UTF-8 text). An `input` written as {repeat: [unit, times], prefix?, suffix?} stands for prefix + unit * times + suffix. Text that looks like a provider key (Slack, Stripe, AWS, GitHub, OpenAI, Anthropic, Google, npm, PEM, JWT) is never stored literally, so secret scanners stay quiet: an `input`, `redact` or `output` written as {join: [part, ...]} stands for the parts concatenated. An implementation passes when every case matches.",
      counts: { total, redact: cases.length, sanitize: sanitize.length, groups },
      cases,
      sanitize,
    },
    null,
    1,
  ) + "\n",
);

/* ------------------------------------------------------------------ page-scan.js */

const script = sdk.buildPageScanScript();
await emit("spec/page-scan.js", script);

/* ------------------------------------------------------------------ copies for the Python package */

await emit("python/src/steplight/_data/page-scan.js", script);
await emit("python/src/steplight/_data/never-capture.json", await readFile(path.join(root, "spec/never-capture.json"), "utf8").catch(() => ""));

if (check) {
  if (stale.length > 0) {
    console.error(`out of date: ${stale.join(", ")}. Run: pnpm -r build && pnpm spec`);
    process.exit(1);
  }
  console.log("spec files are up to date");
} else {
  console.log(`wrote spec/ (${cases.length} redaction cases, ${sanitize.length} sanitize cases) and python/src/steplight/_data/`);
}
