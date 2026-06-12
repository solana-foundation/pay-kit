# Playground snippets — TypeScript

Canonical, runnable source for the code examples shown in the PayKit
Playground under `/charges`, `/subscriptions`, `/sessions`, `/x402`.

## Convention

Each file is named `<primitive>.<side>.ts`:

- `<primitive>` ∈ `charge` | `subscription` | `session` | `x402`
- `<side>` ∈ `client` | `server`

The playground only extracts the region between the two markers:

```ts
// snippet:start
/* …shown verbatim in the playground… */
// snippet:end
```

Everything outside the markers (imports, scaffolding, dummy values) keeps the
file compilable but doesn't appear in the UI. Two literal placeholders are
substituted at render time:

- `'${URL}'` — full endpoint URL; use in **client** snippets.
- `'${PATH}'` — route path only (e.g. `/sessions/stream`); use in **server**
  snippets when registering the route.

## Regenerating the manifest

```sh
pnpm -C playground run gen-snippets
```

Runs automatically via `predev` and `prebuild`. Output:
`playground/app/src/lib/snippets.gen.json`.

## Typechecking

These files are typechecked against the playground server's installed
dependencies (`typescript/examples/playground-api/tsconfig.snippets.json`):

```sh
pnpm -C playground check-snippets
```

Runs as part of `pnpm -C playground build`, so drift against the SDK's
current API fails the playground build.

## Adding a new language

Same layout under `<lang>/docs/snippets/`. The extractor's `ROOTS` table in
`playground/scripts/gen-snippets.mjs` already lists every language; just drop
files into the appropriate directory.

See [`docs/snippets-convention.md`](../../../docs/snippets-convention.md) for
the cross-language conventions.
