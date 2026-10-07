import assert from "node:assert/strict";
import { setTimeout } from "node:timers/promises";
import { generateKeyPairSigner } from "@solana/kit";
import { Mppx, solana } from "@solana/mpp/client";
import { Challenge, Credential } from "mppx";

const signer = await generateKeyPairSigner();
const challenge = Challenge.from({
  id: "gc-regression",
  realm: "harness",
  method: "solana",
  intent: "charge",
  request: {
    amount: "1000",
    currency: "sol",
    recipient: signer.address,
    methodDetails: { decimals: 9, network: "localnet" },
  },
});
const authorization = Credential.serialize({
  challenge,
  payload: { type: "signature", signature: "fixture-signature" },
});

for (const rejectCredential of [false, true]) {
  const challengeResponse = new Response('{"error":"payment_required"}', {
    status: 402,
    headers: { "WWW-Authenticate": Challenge.serialize(challenge) },
  });
  const credentialError = new Error("fixture credential creation failed");
  let calls = 0;
  const client = Mppx.create({
    polyfill: false,
    methods: [solana.charge({ signer })],
    fetch: async (_input, init) => {
      calls++;
      if (calls === 1) return challengeResponse;
      assert.equal(
        new Headers(init?.headers).get("Authorization"),
        authorization,
      );
      return new Response('{"ok":true}', { status: 200 });
    },
    onChallenge: async () => {
      // mppx snapshots the 402 for challenge.received before calling us.
      // Node 22.13's Undici finalizer cancels the ORIGINAL body when that
      // unobserved clone is collected (nodejs/undici#4150, fixed by #4414).
      // Yield between collections so finalizers run while signing is pending.
      assert.ok(globalThis.gc, "Run this fixture with --expose-gc");
      for (let cycle = 0; cycle < 20; cycle++) {
        globalThis.gc();
        await setTimeout(10);
      }
      if (rejectCredential) throw credentialError;
      return authorization;
    },
  });

  if (rejectCredential) {
    // Error reporting must not replace the real error with Response.clone.
    await assert.rejects(
      client.fetch("http://harness.invalid/protected/split-ata-idempotent"),
      (error: unknown) => error === credentialError,
    );
    assert.equal(calls, 1);
  } else {
    const response = await client.fetch(
      "http://harness.invalid/protected/split-ata-idempotent",
    );
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { ok: true });
    assert.equal(calls, 2);
  }
  // Neither the fixture nor the HTTP challenge parser reads this body.
  assert.equal(challengeResponse.bodyUsed, false);
  assert.deepEqual(await challengeResponse.json(), {
    error: "payment_required",
  });
}
