// Shared `allowedPair` policy for x402-exact matrix tests. Keeping the
// policy in one place prevents the e2e and live-matrix tests from
// drifting apart (which would silently create matrix false-negatives).

export const TS_REFERENCE_ID = "ts-x402";
export const RUST_SPINE_PREFIX = "rust-x402";

export function isTsReference(id: string): boolean {
  return id === TS_REFERENCE_ID;
}

export function isRustSpine(id: string): boolean {
  return (
    id === RUST_SPINE_PREFIX ||
    id === `${RUST_SPINE_PREFIX}-client` ||
    id === `${RUST_SPINE_PREFIX}-server`
  );
}

export function baseLang(id: string): string {
  return id.replace(/-client$/, "").replace(/-server$/, "");
}

// Pair restriction: the TS reference adapters speak a stub payload, so
// they only interop with each other. Every other x402-exact adapter
// (Rust spine + language ports) pairs with itself and with the Rust
// spine on either side. Pure language-to-language pairings without
// the spine on one side are out of scope for this matrix.
export function allowedX402Pair(clientId: string, serverId: string): boolean {
  if (isTsReference(clientId) || isTsReference(serverId)) {
    return isTsReference(clientId) && isTsReference(serverId);
  }
  if (isRustSpine(clientId) && isRustSpine(serverId)) return true;
  if (baseLang(clientId) === baseLang(serverId)) return true;
  if (isRustSpine(clientId) || isRustSpine(serverId)) return true;
  return false;
}
