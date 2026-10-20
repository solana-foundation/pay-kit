# Conformance findings

Known gaps referenced from `[[known_failing]]` entries by
`tracking = "FINDINGS.md#<anchor>"`. Each finding should become a GitHub issue;
when it does, replace the tracking value with the issue URL and delete the
section here.

## strict-unclosed-quoted-extension

**Case:** `protocol/challenge.parse :: adversarial_unclosed_quoted_extension`
**SDKs:** typescript, php

The canonical mpp-tools golden parses a `WWW-Authenticate: Payment` header
whose unknown extension auth-param has an unterminated quoted value by
ignoring that param. TypeScript (mppx: "Unterminated quoted-string.") and PHP
("Unterminated quoted value") reject the whole header with `parse_error`.
Both reject immediately, so neither is a ReDoS risk.

The canonical case is assigned to the Python adapter only. pay-kit runs it for
every SDK with a 5 s budget because ReDoS resistance matters to every parser.
The PHP divergence was never observed before 2026-10-20 because spawned
protocol runners only executed one smoke case per operation.

**Decision needed:** whether to follow the canonical lenient behaviour (accept,
drop the malformed param) or to propose the strict behaviour upstream. Until
then both SDKs are listed as known failing; a duration blowout on this case
fails CI regardless of the listing.
