# Codama codegen — Solana program clients

Pay-kit consumes a handful of Solana programs (payment-channels,
subscriptions, …) whose on-chain wire format is best produced from a
single source of truth: each program's Codama IDL. Hand-writing a
client per language is how `rust/crates/kit/src/mpp/program/subscriptions.rs`
became 825 lines that drifted from the upstream IDL the moment a new
field landed.

The tooling under `codegen/` (sibling of this file) automates the
client-generation half of that loop. Today it ships a Rust-only path
for the subscriptions program; extending to TypeScript, Go, Python, …
is a matter of dropping the matching `@codama/renderers-*` into
`codegen/package.json` and adding a recipe.

## Layout

```
skills/pay-sdk-implementation/codegen/
├── package.json                    # pnpm project: Codama + renderers
├── tsconfig.json
├── .gitignore                      # node_modules
└── generate-subscriptions-client.ts

idl/                                # vendored upstream IDLs (repo root)
└── subscriptions.json              # pinned via `subscriptions_ref` in justfile

rust/crates/kit/src/generated/subscriptions/
├── Cargo.toml                      # hand-authored — workspace member
└── src/
    ├── lib.rs                      # `pub mod generated; pub use generated::*;`
    └── generated/                  # WIPED + REWRITTEN by `subscriptions-generate-rs`
        └── …                       # do not hand-edit
```

The split is intentional: the vendored IDL goes at the repository root
(`idl/`) so all language renderers see the same canonical input;
language-specific clients sit alongside the SDKs that consume them
(`rust/crates/kit/src/generated/subscriptions/`, eventually
`typescript/packages/subscriptions-client/`, etc.).

## Pinning the upstream IDL

The justfile at the repo root carries two variables:

```just
subscriptions_repo := "solana-foundation/subscriptions"
subscriptions_ref  := "<git-sha>"
```

Bump the `_ref` SHA when you want a new upstream IDL. `just
subscriptions-pull-idl` fetches the raw file from
`raw.githubusercontent.com` so reproducibility doesn't depend on
whatever `main` happens to be the day someone runs the recipe.

## Daily commands

| Command | What it does |
|---------|--------------|
| `just codegen-install` | `pnpm install` inside the codegen dir. Idempotent. |
| `just subscriptions-pull-idl` | Fetches `idl/subscriptions.json` at the pinned `subscriptions_ref`. |
| `just subscriptions-generate-rs` | Runs Codama with `@codama/renderers-rust`, then `cargo fmt -p solana-pay-kit`. |
| `just subscriptions-sync` | Both of the above. Use this on a clean checkout. |

`subscriptions-generate-rs` is idempotent: it wipes
`rust/crates/kit/src/generated/subscriptions/generated/` before
re-rendering, so a removed instruction in the upstream IDL disappears
on the next run.

## Adding a second language (template)

1. Add the renderer to `codegen/package.json`:

   ```json
   "dependencies": {
     "@codama/renderers-js": "^2.2.0"
   }
   ```

2. Add a sibling script next to `generate-subscriptions-client.ts`:

   ```ts
   import { renderVisitor as renderJsVisitor } from '@codama/renderers-js';
   void codama.accept(renderJsVisitor(tsClientDir, { /* … */ }));
   ```

3. Add a `subscriptions-generate-ts` recipe to the justfile and depend
   on it from `subscriptions-sync`.

The Rust path is the canonical reference; mirror its structure
(`pub mod generated; pub use generated::*;` over a thin wrapper crate)
in each language so the hand-written program-helpers layer (PDA
finders, seed constants, convenience builders) sits cleanly above the
generated tree.

## Why this lives under the skill

This tooling is the implementation of one specific workflow inside the
"port the SDK to language X" skill — Step 5 of the port (consume each
upstream Solana program via its generated client) needs this same
pipeline to be set up for any new language. Keeping it next to the
skill that prescribes the workflow means a contributor reading
`SKILL.md` finds the executable tooling in the same directory tree.
