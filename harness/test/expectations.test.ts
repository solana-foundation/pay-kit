import { describe, expect, it } from "vitest";
import {
  type CaseRef,
  danglingEntries,
  decide,
  parseExpectations,
  reconcile,
} from "../src/expectations";

const toml = `
language = "fake"
[capabilities]
vector = ["charge"]
protocol = true
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
    `language="y"\n[capabilities]\nvector=["charge"]\n[[unsupported]]\nids=["vector/a","vector/b"]\nreason="server-only"`,
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
