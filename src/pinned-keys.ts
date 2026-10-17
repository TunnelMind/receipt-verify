// TunnelMind's published receipt signing-key bundle, shipped with the package
// so the default verify path is bound to a known key without touching the
// network. Copied verbatim from DEFAULT_KEYS_URL on PINNED_KEYS_FETCHED_AT;
// refresh it (and the date) whenever the well-known bundle rotates.

import type { KeyBundle } from './keys.js';

export const PINNED_KEYS_FETCHED_AT = '2026-10-17';

// `as KeyBundle`: the published JSON carries extra fields ($schema,
// verification) that the KeyBundle type does not model; kept for fidelity.
export const PINNED_KEY_BUNDLE: KeyBundle = {
  "$schema": "https://tunnelmind.ai/standards/receipt-format/v1/keys-schema.json",
  "service": "TunnelMind Receipt Format v1.0",
  "spec": "https://tunnelmind.ai/standards/receipt-format/v1",
  "format_version": "1.0",
  "updated_at": "2026-05-31T00:00:00Z",
  "keys": [
    {
      "key_id": "tm-receipt-2026-05",
      "algorithm": "Ed25519",
      "public_key": "U18ONQCXr/Ox3Ac1ShKB1zYRcPIM9Sp9yZrka1jzoCY=",
      "public_key_encoding": "raw-32-byte-base64",
      "status": "active",
      "created_at": "2026-05-31T05:58:00Z",
      "rotation_after": "2027-05-31T00:00:00Z",
      "attestation_strength": "software",
      "operator": "OAI-2026-0000201",
      "purpose": "Signs every TunnelMind Receipt v1.0 envelope produced by scry-server (the producing node). Distinct from the AUDIT_SIGNING_KEY and the ATAP witness key. Key rotation is per-concern: compromise of this key does not compromise audit logs or ATAP witness signatures."
    }
  ],
  "rotation_policy": {
    "scheduled": "SHOULD rotate at or before 12 months from created_at",
    "emergency": "MUST rotate within 1 hour of suspected compromise; overlap window with both keys published for 24h after emergency rotation",
    "overlap_window_hours": 24
  },
  "verification": {
    "instructions": "Resolve the active key whose key_id matches the receipt's signature.key_id. Verify Ed25519 signature against JCS(receipt with payload and signature.value omitted). Reject if the receipt's attestation_strength exceeds this key's attestation_strength. See https://tunnelmind.ai/standards/receipt-format/v1 §4.",
    "reference_verifier": "https://github.com/TunnelMind/receipt-verify"
  }
} as KeyBundle;
