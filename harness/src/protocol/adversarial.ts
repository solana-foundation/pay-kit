// Verdict for a canonically adapter-assigned case (the python-only ReDoS
// probe) run against another adapter for its time bound. The golden encodes
// one parser's leniency toward a header that violates the auth-param
// grammar, which draft-httpauth-payment-00 does not require, so a
// parse_error is also conformant. The time bound applies to both outcomes:
// runCase only times the success path, so the caller passes elapsed time.

export type AdversarialVerdict = { kind: "pass" } | { kind: "golden" } | { kind: "fail"; detail: string };

export function judgeUnassignedCase(
  result: { ok: boolean; detail?: string },
  elapsedMs: number,
  budgetMs: number,
): AdversarialVerdict {
  if (elapsedMs > budgetMs) {
    return { kind: "fail", detail: `duration exceeded: expected <= ${budgetMs} ms, got ${elapsedMs.toFixed(1)} ms` };
  }
  if (result.ok) return { kind: "pass" };
  if (/got error_type=parse_error/.test(result.detail ?? "")) return { kind: "pass" };
  // Any other failure is judged like an assigned case (must match golden).
  return { kind: "golden" };
}
