# MPP protocol conformance vectors (canonical)

These JSON vector files are **imported verbatim** from
[`tempoxyz/mpp-tools`](https://github.com/tempoxyz/mpp-tools)
(`conformance/vectors/`), the canonical IETF-spec conformance suite for the
MPP `Payment` HTTP authentication scheme. They are the protocol **oracle**:
the golden inputs and expected outputs that every pay-kit SDK's protocol
layer (challenge / credential / receipt header codec, base64url, and the
challenge-id HMAC) is validated against.

| File | Operation(s) | Spec reference |
|------|--------------|----------------|
| `www-authenticate.json` | `challenge.parse`, `challenge.format` | draft-ietf-httpauth-payment §5.1 |
| `authorization.json`    | `credential.parse`, `credential.format` | draft-ietf-httpauth-payment §5.2 |
| `receipt.json`          | `receipt.parse`, `receipt.format` | draft-ietf-httpauth-payment §5.3 |
| `base64url.json`        | `base64url.encode`, `base64url.decode` | RFC 4648 §5 |
| `challenge-id.json`     | `challenge.id` (HMAC-SHA256) | draft-ietf-httpauth-payment §5.1.1 |

## Challenge-id derivation (the protocol math)

The challenge id is:

```
base64url( HMAC-SHA256( secretKey,
  realm | method | intent | base64url(JCS(request)) | expires | digest | opaque
) )   // no padding; "|" is a literal pipe; absent optional fields are ""
```

`request` is canonicalized with RFC 8785 JCS (sorted keys, no insignificant
whitespace) and base64url-encoded before it enters the pipe-joined HMAC input.
`opaque` enters the pipe as its already-serialized string form.

## Source / attribution

- Upstream: `tempoxyz/mpp-tools`, `conformance/vectors/`
- Upstream commit: `09b968af5b97abf71df338ec53d6a1ef8380b313` (2026-06-02)
- License: MIT, Copyright (c) 2026 Tempo — see `LICENSE.mpp-tools` in this directory.

Do not hand-edit these files. To refresh, re-copy from the upstream repo and
bump the commit reference above.
