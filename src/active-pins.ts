// The trust roots verifyReceipt uses for TunnelMind's own receipts: the
// pinned key bundle and the pinned log-key document. Not exported from the
// package (package.json "exports" names only "."), so a caller cannot swap
// them; the exported PINNED_* objects are frozen. The test suite imports
// this file by path to put a test key in, because the real pinned keys have
// no private half here.

import type { KeyBundle } from './keys.js';
import type { LogKeyDoc } from './log.js';
import { PINNED_KEY_BUNDLE, PINNED_LOG_KEYS } from './pinned-keys.js';

export const ACTIVE_PINS: { bundle: KeyBundle; logKeys: LogKeyDoc } = {
  bundle: PINNED_KEY_BUNDLE,
  logKeys: PINNED_LOG_KEYS,
};
