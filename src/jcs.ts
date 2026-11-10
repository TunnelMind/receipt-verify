// JCS (RFC 8785) canonicalizer: the bytes every signature and payload_hash
// in this package is computed over. Produces the same bytes as the issuer-side
// serializers (tunnelmind-data-api `api/utils/jcs.js`, scry-server
// `src/lib/receipt_v1.js`) for every well-formed input — the frozen vectors
// in test/vectors/jcs.json pin that — so do not change the output for any
// input a signer can produce: drift breaks every signed receipt.
// One deliberate difference: a lone UTF-16 surrogate throws here where the
// issuers emit U+FFFD, so a receipt containing one fails closed instead of
// two different strings canonicalizing to one signed byte string.
// Input is untrusted parsed JSON; NaN/Infinity (unreachable from JSON.parse)
// throw, `undefined` members are dropped. Never normalizes Unicode: "é" and
// "é" are different strings and hash differently, by design.

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue | undefined };

function encodeString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    // The iterator yields valid pairs as one code point > 0xFFFF, so a cp in
    // this range is a lone surrogate. TextEncoder would map it to U+FFFD and
    // two different strings would canonicalize to the same bytes.
    if (cp >= 0xd800 && cp <= 0xdfff) throw new Error('JCS: lone surrogate in string');
    if (cp === 0x22 || cp === 0x5c) out += '\\' + ch;
    else if (cp === 0x08) out += '\\b';
    else if (cp === 0x09) out += '\\t';
    else if (cp === 0x0a) out += '\\n';
    else if (cp === 0x0c) out += '\\f';
    else if (cp === 0x0d) out += '\\r';
    else if (cp < 0x20) out += '\\u' + cp.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

/** RFC 8785 text of `value`: keys sorted by UTF-16 code units, ES number
 *  formatting, minimal string escapes. Throws on non-finite numbers,
 *  non-JSON types and lone surrogates; `undefined` object members are
 *  dropped (JSON.stringify does the same, so parsed input never has them). */
export function canonicalize(value: JsonValue): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`JCS: non-finite number ${value}`);
    return String(value);
  }
  if (typeof value === 'string') return encodeString(value);
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalize(v as JsonValue)).join(',') + ']';
  if (typeof value === 'object') {
    const v = value as { [k: string]: JsonValue | undefined };
    const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
    return '{' + keys.map((k) => encodeString(k) + ':' + canonicalize(v[k] as JsonValue)).join(',') + '}';
  }
  throw new Error(`JCS: unsupported type ${typeof value}`);
}

export function canonicalizeBytes(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(canonicalize(value));
}

/** `JSON.parse(text)`, but throws `duplicate key "<name>"` when an object
 *  repeats a member name at any depth. Why: JSON.parse silently keeps the
 *  last duplicate while other parsers keep the first (or refuse), so one
 *  receipt text could verify here and mean something else to the next
 *  reader. Names are compared decoded, so "a" and "a" collide;
 *  `__proto__` is an ordinary key (JSON.parse makes it an own property). */
export function parseJsonStrict(text: string): JsonValue {
  // JSON.parse validates and builds the value (its syntax errors propagate);
  // the scan below only runs on text already known to be valid JSON.
  const value = JSON.parse(text) as JsonValue;
  const stack: (Set<string> | null)[] = []; // a Set per open object, null per array
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') { stack.push(new Set()); expectKey = true; }
    else if (c === '[') { stack.push(null); expectKey = false; }
    else if (c === '}' || c === ']') { stack.pop(); expectKey = false; }
    else if (c === ',') expectKey = stack[stack.length - 1] != null;
    else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (expectKey) {
        const name = JSON.parse(text.slice(i, j + 1)) as string;
        const keys = stack[stack.length - 1]!;
        if (keys.has(name)) throw new Error(`duplicate key "${name}"`);
        keys.add(name);
        expectKey = false;
      }
      i = j;
    }
  }
  return value;
}
