// JCS (RFC 8785) canonicalizer — bit-identical to the issuer-side serializers
// in scry-server (`src/lib/receipt_v1.js`) and tunnelmind-data-api
// (`api/utils/receipt-v1.js`). DO NOT diverge: any drift breaks signature
// verification for receipts signed by either issuer.
function encodeString(s) {
    let out = '"';
    for (const ch of s) {
        const cp = ch.codePointAt(0);
        if (cp === 0x22 || cp === 0x5c)
            out += '\\' + ch;
        else if (cp === 0x08)
            out += '\\b';
        else if (cp === 0x09)
            out += '\\t';
        else if (cp === 0x0a)
            out += '\\n';
        else if (cp === 0x0c)
            out += '\\f';
        else if (cp === 0x0d)
            out += '\\r';
        else if (cp < 0x20)
            out += '\\u' + cp.toString(16).padStart(4, '0');
        else
            out += ch;
    }
    return out + '"';
}
export function canonicalize(value) {
    if (value === null)
        return 'null';
    if (typeof value === 'boolean')
        return value ? 'true' : 'false';
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new Error(`JCS: non-finite number ${value}`);
        return String(value);
    }
    if (typeof value === 'string')
        return encodeString(value);
    if (Array.isArray(value))
        return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
    if (typeof value === 'object') {
        const v = value;
        const keys = Object.keys(v).filter((k) => v[k] !== undefined).sort();
        return '{' + keys.map((k) => encodeString(k) + ':' + canonicalize(v[k])).join(',') + '}';
    }
    throw new Error(`JCS: unsupported type ${typeof value}`);
}
export function canonicalizeBytes(value) {
    return new TextEncoder().encode(canonicalize(value));
}
//# sourceMappingURL=jcs.js.map