import { ibanValid, verhoeffValid } from "./checksums.js";
import { compileCustomPatterns } from "./customPatterns.js";

export { luhnValid } from "./checksums.js";

/** Maximum stored size of a request body preview, in characters. */
export const MAX_BODY_PREVIEW = 2 * 1024;
/** Maximum stored size of a snapshot, in characters. */
export const MAX_SNAPSHOT_TEXT = 200 * 1024;

/** What kind of secret or personal data was found. */
export type SensitiveKind =
  | "email"
  | "card"
  | "api_key"
  | "jwt"
  | "private_key"
  | "bearer"
  | "password"
  | "url_param"
  | "iban"
  | "ssn"
  | "aadhaar"
  | "pan"
  | "phone"
  | "encoded"
  | "custom";

/** A sensitive value found in text. */
export interface SensitiveMatch {
  kind: SensitiveKind;
  /** The matched text (do not persist unredacted). */
  value: string;
  index: number;
}

const KIND_LABEL: Record<SensitiveKind, string> = {
  email: "an email address",
  card: "a card-like number",
  api_key: "an API key",
  jwt: "a JWT",
  private_key: "a private key",
  bearer: "a bearer / basic-auth credential",
  password: "a password or secret value",
  url_param: "a secret in a URL parameter",
  iban: "an IBAN",
  ssn: "a US social security number",
  aadhaar: "an Aadhaar number",
  pan: "a PAN number",
  phone: "a phone number",
  encoded: "encoded data that hides a sensitive value",
  custom: "a value matching a custom pattern",
};

/** Human-readable name of a kind, for messages such as "carries an email address". */
export function describeKind(kind: SensitiveKind): string {
  return KIND_LABEL[kind];
}

/* ------------------------------------------------------------------ decoding */

/** Domain part of an email, matched (sticky) right after an `@`. Length-bounded. */
const EMAIL_DOMAIN = /[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,5}\.[A-Za-z]{2,24}/y;

/**
 * Decode percent-escapes so form-encoded values (`a%40b.co`) are visible to the matchers.
 * Invalid sequences are left as-is.
 * @example decodePercent("a%40b.co") // "a@b.co"
 */
export function decodePercent(text: string): string {
  if (!text.includes("%")) return text;
  return text.replace(/(?:%[0-9A-Fa-f]{2})+/g, (m) => {
    try {
      return decodeURIComponent(m);
    } catch {
      return m;
    }
  });
}

/** Percent-decode until nothing changes (defeats `%2540` double encoding), then JSON `\uXXXX` and HTML `&#64;` escapes. */
function decodeAll(input: string): string {
  let text = input;
  for (let i = 0; i < 3; i++) {
    const next = decodePercent(text);
    if (next === text) break;
    text = next;
  }
  if (text.includes("\\")) {
    text = text.replace(/\\u([0-9a-fA-F]{4})/g, (_m, hex: string) => String.fromCharCode(parseInt(hex, 16))).replace(/\\\//g, "/");
  }
  if (text.includes("&#")) {
    text = text.replace(/&#(\d{2,5});|&#x([0-9a-fA-F]{2,4});/g, (m, dec: string | undefined, hex: string | undefined) => {
      const code = dec !== undefined ? Number(dec) : parseInt(hex!, 16);
      return code > 0 && code < 0xd800 ? String.fromCharCode(code) : m;
    });
  }
  return text;
}

/* ------------------------------------------------------------------ matchers */

interface Range {
  start: number;
  end: number;
  kind: SensitiveKind;
  /** Lower wins when ranges overlap. */
  prio: number;
}

type Scanner = (text: string, push: (start: number, end: number, kind: SensitiveKind, prio: number) => void) => void;

function isLocalChar(code: number): boolean {
  return (
    (code >= 48 && code <= 57) || // 0-9
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    code === 46 || code === 95 || code === 37 || code === 43 || code === 45 // . _ % + -
  );
}

/**
 * Find email addresses. Anchored on `@` (found with indexOf) so cost is linear in the text
 * length plus at most ~64 characters of lookback per `@`; no regex backtracking over the
 * whole input.
 * @example findEmails("mail a@b.co now") // [{ value: "a@b.co", index: 5 }]
 */
export function findEmails(text: string): { value: string; index: number }[] {
  const out: { value: string; index: number }[] = [];
  let from = 0;
  for (;;) {
    const at = text.indexOf("@", from);
    if (at < 0) break;
    from = at + 1;
    let start = at;
    while (start > 0 && at - start < 64 && isLocalChar(text.charCodeAt(start - 1))) start--;
    if (start === at) continue;
    EMAIL_DOMAIN.lastIndex = at + 1;
    const m = EMAIL_DOMAIN.exec(text);
    if (!m) continue;
    const end = at + 1 + m[0].length;
    out.push({ value: text.slice(start, end), index: start });
    from = end;
  }
  return out;
}

/** Cheap pre-check: run the (more expensive) regex only if one of these literals occurs in the text. */
const hasAny = (text: string, needles: readonly string[]): boolean => needles.some((n) => text.includes(n));

const regexScanner =
  (
    re: RegExp,
    kind: SensitiveKind,
    prio: number,
    accept?: (value: string, text: string, index: number) => boolean,
    needles?: readonly string[],
  ): Scanner =>
  (text, push) => {
    if (needles && !hasAny(text, needles)) return;
    for (const m of text.matchAll(re)) {
      const index = m.index ?? 0;
      if (accept && !accept(m[0], text, index)) continue;
      push(index, index + m[0].length, kind, prio);
    }
  };

/** PEM private key blocks. Linear: uses indexOf, and an unterminated block runs to the end (fail closed). */
const privateKeys: Scanner = (text, push) => {
  let from = 0;
  for (;;) {
    const begin = text.indexOf("-----BEGIN ", from);
    if (begin < 0) return;
    const headerEnd = text.indexOf("-----", begin + 11);
    if (headerEnd < 0 || !/PRIVATE KEY/.test(text.slice(begin, headerEnd + 5))) {
      from = begin + 11;
      continue;
    }
    const endMarker = text.indexOf("-----END ", headerEnd);
    if (endMarker < 0) return void push(begin, text.length, "private_key", 0);
    const endClose = text.indexOf("-----", endMarker + 9);
    const end = endClose < 0 ? text.length : endClose + 5;
    push(begin, end, "private_key", 0);
    from = end;
  }
};

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
/** OpenAI / Anthropic (`sk-…`), AWS access key ids, GitHub, Slack, Stripe, Google and npm tokens. */
const API_KEYS: readonly (readonly [RegExp, readonly string[]])[] = [
  [/\bsk-(?:proj-|ant-(?:api\d{2}-)?)?[A-Za-z0-9_-]{16,200}\b/g, ["sk-"]],
  [/\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}/g, ["AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "AIPA"]],
  [/\bgh[pousr]_[A-Za-z0-9]{30,100}\b/g, ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]],
  [/\bgithub_pat_[A-Za-z0-9_]{50,120}\b/g, ["github_pat_"]],
  [/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, ["xox"]],
  [/\bxapp-[0-9]-[A-Za-z0-9-]{10,}/g, ["xapp-"]],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,100}\b/g, ["k_live_", "k_test_"]],
  [/\bwhsec_[A-Za-z0-9]{16,100}\b/g, ["whsec_"]],
  [/\bAIza[0-9A-Za-z_-]{35}/g, ["AIza"]],
  [/\bnpm_[A-Za-z0-9]{36}/g, ["npm_"]],
];
const BEARER = /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}/gi;

/** `password=…`, `"secret": "…"`, `api_key: …`. Only the value is redacted. */
const PASSWORD_PAIR =
  /(?<![A-Za-z0-9])(?:pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|refresh[_-]?token|client[_-]?secret|private[_-]?key|credentials?)s?(["']?[ \t]{0,3}[:=][ \t]{0,3}["']?)([^\s"'&;,<>\\]{3,200})/gi;
/**
 * A value that is one redaction marker (plus trailing punctuation the value pattern swallowed, like the `;` of a
 * cookie) was redacted already: leave it, so redacting twice changes nothing. Anything else after the marker is
 * still redacted.
 */
const isMarker = (value: string): boolean => /^\[REDACTED:[a-z_]+\][;,.)\]}]*$/.test(value);

const passwordPairs: Scanner = (text, push) => {
  if (!text.includes(":") && !text.includes("=")) return;
  for (const m of text.matchAll(PASSWORD_PAIR)) {
    if (isMarker(m[3]!)) continue;
    const end = (m.index ?? 0) + m[0].length;
    push(end - m[2]!.length, end, "password", 4);
  }
};

/** Query / form parameters whose name says they carry a secret. Only the value is redacted. */
const URL_PARAM =
  /(?<=^|[?&;#\s])(?:[a-z0-9_.-]*(?:token|secret|password|passwd|pwd|signature|credential|apikey|api[_-]key)|key|code|session(?:id)?|sid|auth(?:orization)?|sig|otp|jwt)=([^&\s#"'<>]{1,500})/gi;
const urlParams: Scanner = (text, push) => {
  if (!text.includes("=")) return;
  for (const m of text.matchAll(URL_PARAM)) {
    if (isMarker(m[1]!)) continue;
    const end = (m.index ?? 0) + m[0].length;
    push(end - m[1]!.length, end, "url_param", 5);
  }
};

const emails: Scanner = (text, push) => {
  for (const e of findEmails(text)) push(e.index, e.index + e.value.length, "email", 6);
};

const IBAN = /(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?(?![A-Z0-9])/g;
const SSN = /(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)/g;

/**
 * Card numbers: digit groups joined by a single space or dash. Every run of 13–19 digits that
 * starts and ends on a group boundary is Luhn-checked, so a card next to another number
 * ("order 12345 4242 4242 4242 4242") is still found. Each window is checked in O(1) using
 * prefix sums, so the scan is linear even for a megabyte of "1 1 1 1 …".
 */
const cards: Scanner = (text, push) => {
  const n = text.length;
  const starts: number[] = [];
  const ends: number[] = [];
  const flush = (): void => {
    const g = starts.length;
    let total = 0;
    for (let k = 0; k < g; k++) total += ends[k]! - starts[k]!;
    if (total >= 13) {
      // Per-digit values and prefix sums split by index parity: raw digit and Luhn-doubled digit.
      const rawE = new Int32Array(total + 1);
      const rawO = new Int32Array(total + 1);
      const dblE = new Int32Array(total + 1);
      const dblO = new Int32Array(total + 1);
      const offset = new Int32Array(g + 1);
      let idx = 0;
      for (let k = 0; k < g; k++) {
        offset[k] = idx;
        for (let c = starts[k]!; c < ends[k]!; c++, idx++) {
          const d = text.charCodeAt(c) - 48;
          const dd = d * 2 > 9 ? d * 2 - 9 : d * 2;
          rawE[idx + 1] = rawE[idx]! + (idx % 2 === 0 ? d : 0);
          rawO[idx + 1] = rawO[idx]! + (idx % 2 === 1 ? d : 0);
          dblE[idx + 1] = dblE[idx]! + (idx % 2 === 0 ? dd : 0);
          dblO[idx + 1] = dblO[idx]! + (idx % 2 === 1 ? dd : 0);
        }
      }
      offset[g] = idx;
      /** Luhn sum of digits [a, b): digits at an even distance from the end are kept, the others doubled. */
      const valid = (from: number, to: number): boolean => {
        const keepOdd = (to - 1) % 2 === 1; // parity of the index that is kept as-is
        const raw = keepOdd ? rawO[to]! - rawO[from]! : rawE[to]! - rawE[from]!;
        const dbl = keepOdd ? dblE[to]! - dblE[from]! : dblO[to]! - dblO[from]!;
        return (raw + dbl) % 10 === 0;
      };
      for (let s = 0; s < g; s++) {
        let best = -1;
        for (let e = s; e < g; e++) {
          const len = offset[e + 1]! - offset[s]!;
          if (len > 19) break;
          if (len >= 13 && valid(offset[s]!, offset[e + 1]!)) best = e;
        }
        if (best >= 0) {
          push(starts[s]!, ends[best]!, "card", 9);
          s = best; // continue after this card
        }
      }
    }
    starts.length = 0;
    ends.length = 0;
  };
  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    if (c < 48 || c > 57) {
      i++;
      continue;
    }
    let j = i;
    while (j < n && text.charCodeAt(j) >= 48 && text.charCodeAt(j) <= 57) j++;
    const last = ends.length - 1;
    if (last >= 0 && !(i - ends[last]! === 1 && (text[ends[last]!] === " " || text[ends[last]!] === "-"))) flush();
    starts.push(i);
    ends.push(j);
    i = j;
  }
  flush();
};

const AADHAAR_GROUPED = /(?<!\d)[2-9]\d{3}[ -]\d{4}[ -]\d{4}(?!\d)/g;
const AADHAAR_PLAIN = /(?<!\d)[2-9]\d{11}(?!\d)/g;
const PAN = /(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Z0-9])/g;

/** A plain 12-digit number is only treated as Aadhaar when the text around it says so. */
const aadhaarContext = (text: string, index: number): boolean =>
  /aadh?a{1,2}r|uidai|\buid\b/i.test(text.slice(Math.max(0, index - 40), index));

const PHONE_CANDIDATE = /(?<![\d@.])\+?\(?\d[\d ()\-.]{6,20}\d(?![\d@])/g;
const NANP = /^\(?[2-9]\d{2}\)?[ .-]\d{3}[ .-]\d{4}$/;
/** A phone number as a whole? International (`+…`), Indian mobile, or North-American. */
function isPhone(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, "");
  if (candidate.startsWith("+")) return digits.length >= 8 && digits.length <= 15;
  const rest = digits.length === 12 && digits.startsWith("91") ? digits.slice(2) : digits.length === 11 && digits.startsWith("0") ? digits.slice(1) : digits.length === 10 ? digits : "";
  return /^[6-9]\d{9}$/.test(rest) || NANP.test(candidate);
}
/**
 * Phone numbers: international (`+…`, 8–15 digits), Indian mobiles (10 digits starting 6–9, with an
 * optional +91 / 91 / 0) and North-American numbers. A candidate that is not a phone as a whole is
 * retried by dropping leading/trailing tokens, so "total 1,499 98765 43210" still finds the number.
 */
const phones: Scanner = (text, push) => {
  for (const m of text.matchAll(PHONE_CANDIDATE)) {
    const base = m.index ?? 0;
    const candidate = m[0];
    if (isPhone(candidate)) {
      push(base, base + candidate.length, "phone", 14);
      continue;
    }
    // Token boundaries inside the candidate (positions right after a separator run).
    const tokens: { start: number; end: number }[] = [];
    for (const t of candidate.matchAll(/[+(]?\d[\d)]*(?:[.-]\d+)*/g)) tokens.push({ start: t.index ?? 0, end: (t.index ?? 0) + t[0].length });
    if (tokens.length < 2 || tokens.length > 8) continue;
    let found = false;
    for (let from = 0; from < tokens.length && !found; from++) {
      for (let to = tokens.length - 1; to >= from && !(from === 0 && to === tokens.length - 1); to--) {
        const part = candidate.slice(tokens[from]!.start, tokens[to]!.end);
        if (isPhone(part)) {
          push(base + tokens[from]!.start, base + tokens[to]!.end, "phone", 14);
          found = true;
          break;
        }
      }
    }
  }
};

const MARKER = /\[REDACTED:(email|card|api_key|jwt|private_key|bearer|iban|ssn|aadhaar|pan|encoded|password|url_param)\]/g;
/** Text already redacted at the source still tells detectors that a secret was there. */
const markers =
  (credentials: boolean): Scanner =>
  (text, push) => {
    for (const m of text.matchAll(MARKER)) {
      const kind = m[1] as SensitiveKind;
      if (!credentials && (kind === "password" || kind === "url_param")) continue;
      push(m.index ?? 0, (m.index ?? 0) + m[0].length, kind, 1);
    }
  };

const BASE64_TOKEN = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{24,}={0,2}(?![A-Za-z0-9+/_=-])/g;
const MAX_ENCODED_TOKENS = 300;
const MAX_ENCODED_CHARS = 4096;

/** Decode a base64 / base64url token to text, or undefined when it is not mostly printable. */
function decodeBase64Text(token: string): string | undefined {
  try {
    let b64 = token.slice(0, MAX_ENCODED_CHARS).replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
    b64 = b64.slice(0, b64.length - (b64.length % 4 === 1 ? 1 : 0));
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    let printable = 0;
    for (let i = 0; i < bin.length; i++) {
      const c = bin.charCodeAt(i);
      if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) printable++;
    }
    return bin.length > 0 && printable / bin.length >= 0.9 ? bin : undefined;
  } catch {
    return undefined;
  }
}

/** Base64-looking segments that decode to text containing a sensitive value (an obfuscated exfiltration). */
const encodedSegments =
  (inner: (decoded: string) => boolean): Scanner =>
  (text, push) => {
    let count = 0;
    for (const m of text.matchAll(BASE64_TOKEN)) {
      if (++count > MAX_ENCODED_TOKENS) return;
      if (/^[A-Za-z]+$/.test(m[0]) && m[0].length < 40) continue; // an ordinary long word
      const decoded = decodeBase64Text(m[0]);
      if (decoded !== undefined && inner(decoded)) push(m.index ?? 0, (m.index ?? 0) + m[0].length, "encoded", 2);
    }
  };

/* ------------------------------------------------------------------ custom patterns */

let customRegexes: RegExp[] = [];

/**
 * Set the user's extra redaction patterns. Each is validated (syntax, size, nested repetition,
 * timing test) and silently skipped if it fails, so a bad pattern can never hang or crash
 * redaction. Pass an empty list to clear.
 * @example configureRedaction({ customPatterns: ["EMP-\\d{6}"] })
 */
export function configureRedaction(options: { customPatterns?: readonly string[] }): void {
  customRegexes = compileCustomPatterns(options.customPatterns ?? []);
}

const customScanner: Scanner = (text, push) => {
  for (const re of customRegexes) {
    for (const m of text.matchAll(new RegExp(re.source, re.flags))) {
      if (m[0].length === 0) continue;
      push(m.index ?? 0, (m.index ?? 0) + m[0].length, "custom", 15);
    }
  }
};

/* ------------------------------------------------------------------ scanning */

interface ScanOptions {
  /** Include password pairs and secret-looking URL parameters (a login form to its own site is normal). */
  credentials: boolean;
  /** Include phone numbers and the user's custom patterns (redaction only; too noisy for flags). */
  extended: boolean;
  /** Recognise `[REDACTED:…]` markers left by redaction at the source. */
  markers: boolean;
}

function baseScanners(o: ScanOptions): Scanner[] {
  const list: Scanner[] = [
    privateKeys,
    regexScanner(JWT, "jwt", 3, undefined, ["eyJ"]),
    ...API_KEYS.map(([re, needles]) => regexScanner(re, "api_key", 3, undefined, needles)),
    regexScanner(BEARER, "bearer", 3, undefined, ["earer", "EARER", "asic", "ASIC"]),
    emails,
    regexScanner(IBAN, "iban", 7, (v) => ibanValid(v)),
    regexScanner(SSN, "ssn", 8, undefined, ["-"]),
    cards,
    regexScanner(AADHAAR_GROUPED, "aadhaar", 10, (v) => verhoeffValid(v), [" ", "-"]),
    regexScanner(AADHAAR_PLAIN, "aadhaar", 10, (v, text, i) => verhoeffValid(v) && aadhaarContext(text, i)),
    regexScanner(PAN, "pan", 11),
  ];
  if (o.credentials) list.push(passwordPairs, urlParams);
  if (o.extended) list.push(phones);
  return list;
}

function collect(text: string, o: ScanOptions, nested = false): Range[] {
  const found: Range[] = [];
  const push = (start: number, end: number, kind: SensitiveKind, prio: number): void => {
    if (end > start) found.push({ start, end, kind, prio });
  };
  for (const scanner of baseScanners(o)) scanner(text, push);
  if (o.markers) markers(o.credentials)(text, push);
  if (o.extended) customScanner(text, push);
  if (!nested && text.length >= 24) {
    // Obfuscated copies: base64 that decodes to something sensitive.
    encodedSegments((decoded) => collect(decoded, { ...o, markers: false }, true).length > 0)(text, push);
  }
  // Overlaps: earlier start wins, then the more specific (lower prio) kind, then the longer range.
  found.sort((a, b) => a.start - b.start || a.prio - b.prio || b.end - a.end);
  const out: Range[] = [];
  let lastEnd = 0;
  for (const r of found) {
    if (r.start < lastEnd) continue;
    out.push(r);
    lastEnd = r.end;
  }
  return out;
}

/**
 * Find secrets and personal data that detectors should react to: emails, Luhn-valid cards, API
 * keys (OpenAI, Anthropic, AWS, GitHub, Slack, Stripe, Google, npm), JWTs, private keys,
 * bearer/basic credentials, IBANs (mod 97), US SSNs, Aadhaar (Verhoeff), PAN, and base64 that
 * hides any of those. Percent-, JSON- and HTML-escapes are decoded first, and `[REDACTED:…]`
 * markers left by redaction at the source count as findings. With `credentials: true`,
 * `password=…` pairs and secret-looking URL parameters are included too.
 * Phone numbers are deliberately not reported here (too many look-alikes); they are redacted.
 * @example findSensitive("mail me at a@b.co") // [{ kind: "email", ... }]
 */
export function findSensitive(input: string, options: { credentials?: boolean } = {}): SensitiveMatch[] {
  const text = decodeAll(input);
  return collect(text, { credentials: options.credentials === true, extended: false, markers: true }).map((r) => ({
    kind: r.kind,
    value: text.slice(r.start, r.end),
    index: r.start,
  }));
}

/**
 * Replace every sensitive value with `[REDACTED:<kind>]`: everything {@link findSensitive} knows,
 * plus passwords, secret URL parameters, phone numbers and the user's custom patterns.
 * Text without findings is returned unchanged; otherwise escapes are decoded in the result.
 * Applying it twice gives the same result.
 * @example redactText("mail jane@example.com") // "mail [REDACTED:email]"
 */
export function redactText(input: string): string {
  try {
    const text = decodeAll(input);
    const ranges = collect(text, { credentials: true, extended: true, markers: false });
    if (ranges.length === 0) return input;
    let out = "";
    let pos = 0;
    for (const r of ranges) {
      out += `${text.slice(pos, r.start)}[REDACTED:${r.kind}]`;
      pos = r.end;
    }
    return out + text.slice(pos);
  } catch {
    // Fail closed: if redaction itself breaks, the data is dropped rather than kept raw.
    return "[REDACTED:error]";
  }
}

/* ------------------------------------------------------------------ evidence & truncation */

/**
 * Short masked form of a secret for use as flag evidence, e.g. `sk-a…vwxy`.
 * @example maskValue("sk-abcdefghijklmnop") // "sk-a…mnop"
 */
export function maskValue(value: string): string {
  return value.length <= 8 ? "••••" : `${value.slice(0, 4)}…${value.slice(-4)}`;
}

/**
 * Evidence-safe description of a sensitive match: never reveals more than needed to
 * recognise it (email → domain only, card → last 4, key/JWT → short prefix).
 * @example maskSensitive({ kind: "email", value: "jane@example.com", index: 0 }) // "••••@example.com"
 */
export function maskSensitive(match: SensitiveMatch): string {
  const { kind, value } = match;
  if (value.startsWith("[REDACTED:")) return "[redacted at source]";
  switch (kind) {
    case "email":
      return `••••${value.slice(value.indexOf("@"))}`;
    case "card":
    case "aadhaar":
    case "phone":
      return `•••• ${value.replace(/\D/g, "").slice(-4)}`;
    case "ssn":
      return `•••-••-${value.slice(-4)}`;
    case "iban":
      return `${value.slice(0, 2)}•• ••••`;
    case "pan":
      return "•••••••••" + value.slice(-1);
    case "password":
    case "url_param":
    case "private_key":
    case "bearer":
    case "encoded":
    case "custom":
      return "••••";
    default:
      return `${value.slice(0, kind === "jwt" ? 3 : 4)}…`;
  }
}

/**
 * Truncate text to a maximum length, appending a marker when cut.
 * @example truncate("abcdef", 3) // "abc…[truncated]"
 */
export function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max)}…[truncated]`;
}

/**
 * Redact then truncate a request body preview to {@link MAX_BODY_PREVIEW}.
 * @example sanitizeBody("email=a@b.co") // "email=[REDACTED:email]"
 */
export function sanitizeBody(body: string): string {
  return redactText(truncate(body, MAX_BODY_PREVIEW));
}

/**
 * Redact then truncate snapshot text to {@link MAX_SNAPSHOT_TEXT}.
 * @example sanitizeSnapshot(pageText)
 */
export function sanitizeSnapshot(text: string): string {
  // Truncate first to bound regex work, then redact. A secret split at the cut point could
  // leave a short fragment; that is an accepted trade-off (see DECISIONS.md).
  return redactText(truncate(text, MAX_SNAPSHOT_TEXT));
}
