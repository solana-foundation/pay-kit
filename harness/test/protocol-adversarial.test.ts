import { describe, expect, it } from "vitest";
import { judgeUnassignedCase } from "../src/protocol/adversarial";

describe("unassigned adversarial cases", () => {
  const parseError = { ok: false, detail: "expected success, got error_type=parse_error (Unterminated)" };

  it("accepts a fast golden result or a fast parse_error", () => {
    expect(judgeUnassignedCase({ ok: true }, 10, 5000).kind).toBe("pass");
    expect(judgeUnassignedCase(parseError, 10, 5000).kind).toBe("pass");
  });

  it("fails a slow parse_error, not only a slow parse", () => {
    const verdict = judgeUnassignedCase(parseError, 6000, 5000);
    expect(verdict.kind).toBe("fail");
    expect(verdict.kind === "fail" && verdict.detail).toMatch(/duration exceeded/);
    expect(judgeUnassignedCase({ ok: true }, 6000, 5000).kind).toBe("fail");
  });

  it("falls back to the golden comparison for any other failure", () => {
    expect(judgeUnassignedCase({ ok: false, detail: "semantic mismatch" }, 10, 5000).kind).toBe("golden");
  });
});
