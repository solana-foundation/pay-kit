/**
 * Coverage for the in-repo challenge-parse guard (shared/challenge-guard.ts).
 *
 * - empty-id rejection (pre-existing canonical-conformance guard)
 * - oversized-header size cap (audit #9): mppx's WWW-Authenticate parser
 *   base64-decodes + JSON-parses the embedded `request` param with no cap, a
 *   client-side DoS surface. We cap the full header at our boundary.
 */
import { test, expect } from 'vitest';

import { deserialize, deserializeList, MAX_CHALLENGE_HEADER_LEN } from '../shared/challenge-guard.js';

test('#9 deserialize rejects an oversized challenge header before parsing', () => {
    const oversized = 'Payment ' + 'A'.repeat(MAX_CHALLENGE_HEADER_LEN + 1);
    expect(() => deserialize(oversized)).toThrow(/exceeds maximum size/);
});

test('#9 deserializeList rejects an oversized challenge header before parsing', () => {
    const oversized = 'Payment ' + 'A'.repeat(MAX_CHALLENGE_HEADER_LEN + 1);
    expect(() => deserializeList(oversized)).toThrow(/exceeds maximum size/);
});

test('#9 deserialize does not fire the size cap for a normal-length (malformed) header', () => {
    // A short, malformed header should fail somewhere other than the size cap.
    expect(() => deserialize('Payment id=""')).not.toThrow(/exceeds maximum size/);
});
