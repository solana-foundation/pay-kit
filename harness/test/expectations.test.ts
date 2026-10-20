import { afterEach, describe, expect, it, vi } from "vitest";
import {
  type CaseRef,
  danglingEntries,
  decide,
  parseExpectations,
  reconcile,
} from "../src/expectations";
import { assertSuiteComplete, CaseRecorder, resetRecordersForTest } from "../src/expectations-run";

const toml = `
language = "fake"
[capabilities]
vector = ["charge"]
protocol = true
honours_clock = true
[[unsupported]]
pattern = "vector/charge-verify-*"
reason = "client-only"
[[known_failing]]
id = "vector/charge-build-broken"
reason = "decimals default"
tracking = "FINDINGS.md#fake-decimals"
`;

const exp = parseExpectations(toml, "fake.toml");
const ref = (id: string, capability = "charge", suite: CaseRef["suite"] = "vector"): CaseRef => ({
  suite,
  id,
  capability,
});

describe("expectations parsing", () => {
  it("rejects unknown keys, missing tracking and bad tracking", () => {
    expect(() => parseExpectations(`language="x"\nfoo=1`, "x.toml")).toThrow(/unknown top-level/);
    expect(() =>
      parseExpectations(`language="x"\n[[known_failing]]\nid="vector/a"\nreason="r"`, "x.toml"),
    ).toThrow(/tracking/);
    expect(() =>
      parseExpectations(
        `language="x"\n[[known_failing]]\nid="vector/a"\nreason="r"\ntracking="TODO"`,
        "x.toml",
      ),
    ).toThrow(/tracking/);
  });

  it("rejects a misspelled vector intent claim", () => {
    expect(() =>
      parseExpectations(`language="x"\n[capabilities]\nvector=["x402-exat"]`, "x.toml"),
    ).toThrow(/unknown vector intent "x402-exat"/);
    expect(parseExpectations(`language="x"\n[capabilities]\nvector=["x402-exact"]\nhonours_clock=false`, "x.toml").capabilities.vector.has("x402-exact")).toBe(true);
  });

  it("requires honours_clock when vectors are claimed (no default)", () => {
    expect(() => parseExpectations(`language="x"\n[capabilities]\nvector=["charge"]`, "x.toml")).toThrow(/honours_clock/);
    expect(() =>
      parseExpectations(`language="x"\n[capabilities]\nvector=["charge"]\nhonours_clock="yes"`, "x.toml"),
    ).toThrow(/must be a boolean/);
    expect(parseExpectations(`language="x"\n[capabilities]\nvector=["charge"]\nhonours_clock=true`, "x.toml").honoursClock).toBe(true);
  });

  it("rejects entries for an unclaimed suite", () => {
    expect(() =>
      parseExpectations(`language="x"\n[[unsupported]]\nids=["protocol/a"]\nreason="r"`, "x.toml"),
    ).toThrow(/does not claim the protocol suite/);
  });

  it("rejects ids without a suite prefix", () => {
    expect(() =>
      parseExpectations(`language="x"\n[[unsupported]]\nids=["charge-a"]\nreason="r"`, "x.toml"),
    ).toThrow(/must start with/);
  });

  it("rejects an unsupported entry without a reason", () => {
    expect(() =>
      parseExpectations(`language="x"\n[[unsupported]]\npattern="vector/*"\nreason=""`, "x.toml"),
    ).toThrow(/reason/);
  });
});

describe("decide", () => {
  it("classifies every case into exactly one bucket", () => {
    expect(decide(exp, ref("x402-basic", "x402-exact")).kind).toBe("unclaimed");
    expect(decide(exp, ref("charge-verify-ok")).kind).toBe("unsupported");
    expect(decide(exp, ref("charge-build-broken")).kind).toBe("known_failing");
    expect(decide(exp, ref("charge-build-ok")).kind).toBe("pass");
    expect(decide(exp, ref("flow-a", "flow", "flow")).kind).toBe("unclaimed");
  });
});

describe("reconcile is exact in both directions", () => {
  const pass = { kind: "pass" } as const;
  const failed = { kind: "fail", detail: "boom" } as const;
  const unsupported = { kind: "unsupported", detail: "unsupported-mode" } as const;

  it("positive controls", () => {
    const r1 = ref("charge-build-ok");
    expect(reconcile(exp, r1, decide(exp, r1), pass).ok).toBe(true);
    const r2 = ref("charge-build-broken");
    expect(reconcile(exp, r2, decide(exp, r2), failed).ok).toBe(true);
    const r3 = ref("charge-verify-ok");
    expect(reconcile(exp, r3, decide(exp, r3), unsupported).ok).toBe(true);
  });

  it("an unlisted failure fails", () => {
    const r = ref("charge-build-ok");
    const v = reconcile(exp, r, decide(exp, r), failed);
    expect(v.ok).toBe(false);
    expect(v.message).toMatch(/known_failing in harness\/expectations\/fake\.toml/);
  });

  it("a listed failure that passes fails", () => {
    const r = ref("charge-build-broken");
    const v = reconcile(exp, r, decide(exp, r), pass);
    expect(v.ok).toBe(false);
    expect(v.message).toMatch(/now passes; remove it/);
  });

  it("an unlisted unsupported result fails", () => {
    const r = ref("charge-build-ok");
    expect(reconcile(exp, r, decide(exp, r), unsupported).ok).toBe(false);
  });

  it("a stale unsupported entry fails", () => {
    const r = ref("charge-verify-ok");
    expect(reconcile(exp, r, decide(exp, r), pass).ok).toBe(false);
    expect(reconcile(exp, r, decide(exp, r), failed).ok).toBe(false);
  });
});

describe("dangling entries", () => {
  it("only checks entries of the suite being run", () => {
    expect(danglingEntries(exp, "protocol", [])).toEqual([]);
  });

  it("flags entries that match no claimed case", () => {
    expect(danglingEntries(exp, "vector", [ref("charge-build-ok")])).toEqual([
      'unsupported pattern "vector/charge-verify-*" matches no claimed case',
      'known_failing "vector/charge-build-broken" matches no claimed case',
    ]);
    expect(
      danglingEntries(exp, "vector", [ref("charge-verify-ok"), ref("charge-build-broken")]),
    ).toEqual([]);
  });
});

describe("unsupported id lists", () => {
  const listed = parseExpectations(
    `language="y"\n[capabilities]\nvector=["charge"]\nhonours_clock=true\n[[unsupported]]\nids=["vector/a","vector/b"]\nreason="server-only"`,
    "y.toml",
  );
  it("matches exactly the listed ids", () => {
    expect(decide(listed, ref("a")).kind).toBe("unsupported");
    expect(decide(listed, ref("b")).kind).toBe("unsupported");
    expect(decide(listed, ref("ab")).kind).toBe("pass");
  });
  it("reports each stale id individually", () => {
    expect(danglingEntries(listed, "vector", [ref("a")])).toEqual(['unsupported id "vector/b" matches no claimed case']);
  });
  it("rejects pattern and ids together, and duplicate ids", () => {
    expect(() =>
      parseExpectations(`language="y"\n[[unsupported]]\nids=["vector/a"]\npattern="x"\nreason="r"`, "y.toml"),
    ).toThrow(/exactly one/);
    expect(() =>
      parseExpectations(
        `language="y"\n[[unsupported]]\nids=["vector/a"]\nreason="r"\n[[unsupported]]\nids=["vector/a"]\nreason="s"`,
        "y.toml",
      ),
    ).toThrow(/duplicate/);
  });
});

describe("file-level completeness", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    resetRecordersForTest();
  });

  const claimed = parseExpectations(`language="a"\n[capabilities]\nvector=["charge"]\nhonours_clock=true`, "a.toml");
  const refs = [ref("c1"), ref("c2")];

  it("fails when a whole language was filtered out", () => {
    vi.stubEnv("HARNESS_REQUIRE", "1");
    const ran = new CaseRecorder("vector", "ran").expect(refs, claimed);
    for (const r of refs) ran.record(r, { kind: "pass" }, { kind: "pass" });
    new CaseRecorder("vector", "filtered").expect(refs, claimed); // its tests never ran
    expect(() => assertSuiteComplete("vector")).toThrow(/filtered: 2 claimed vector case/);
  });

  it("passes when every selected language executed its claims (control)", () => {
    vi.stubEnv("HARNESS_REQUIRE", "1");
    const ran = new CaseRecorder("vector", "ran").expect(refs, claimed);
    for (const r of refs) ran.record(r, { kind: "pass" }, { kind: "pass" });
    expect(() => assertSuiteComplete("vector")).not.toThrow();
  });

  it("only enforces under HARNESS_REQUIRE=1", () => {
    // CI runs this file with HARNESS_REQUIRE=1, so set the opposite explicitly.
    vi.stubEnv("HARNESS_REQUIRE", "0");
    new CaseRecorder("vector", "filtered").expect(refs, claimed);
    expect(() => assertSuiteComplete("vector")).not.toThrow();
  });
});
