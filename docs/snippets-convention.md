# Playground snippets convention

The PayKit Playground (`playground/app`) shows a runnable client / server
example per language for each protected-endpoint primitive. To keep the
snippets DRY and rot-proof, the playground extracts them from real example
files inside each language's own source tree.

## TL;DR for contributors

1. Put your snippet in `<lang>/docs/snippets/<primitive>.<side>.<ext>`.
2. Wrap the relevant region with `snippet:start` … `snippet:end` markers.
3. Use the literal token `'${URL}'` (client snippets) or `'${PATH}'` (server
   snippets) where the endpoint goes.
4. Run `pnpm -C playground run gen-snippets`.

The playground picks it up automatically.

## File layout

All nine languages follow the same path — `<lang>/docs/snippets/`:

| Language   | Root                          |
|------------|-------------------------------|
| typescript | `typescript/docs/snippets/`   |
| rust       | `rust/docs/snippets/`         |
| go         | `go/docs/snippets/`           |
| python     | `python/docs/snippets/`       |
| ruby       | `ruby/docs/snippets/`         |
| php        | `php/docs/snippets/`          |
| lua        | `lua/docs/snippets/`          |
| kotlin     | `kotlin/docs/snippets/`       |
| swift      | `swift/docs/snippets/`        |

Adjust the table by editing the `ROOTS` map in
`playground/scripts/gen-snippets.mjs`.

## File naming

```
<primitive>.<side>.<ext>
```

* `<primitive>` ∈ `charge` | `subscription` | `session` | `x402`
* `<side>` ∈ `client` | `server`
* `<ext>` whatever your language uses (`.ts`, `.rs`, `.py`, `.go`, …)

Anything that doesn't match is ignored — feel free to keep other examples in
the same directory.

Some languages only ship one side (kotlin / swift are client-only, go / ruby
/ php / lua are server-only). Just omit the file you don't have.

## Marker convention

```
// snippet:start
…the region rendered verbatim in the playground…
// snippet:end
```

* Any comment syntax works (`//`, `#`, `--`, `/* … */` on a separate line).
* The line containing the marker may have anything before it, but **nothing
  but horizontal whitespace after it** — that's how the extractor
  distinguishes a real marker from a prose mention.
* Leading common indentation is stripped, so the snippet renders flush in
  the UI even if the marker sits inside a function body.

## Endpoint placeholders

Two literal tokens are substituted at render time (keep the single quotes):

* `'${URL}'` — the **full endpoint URL** the user has selected (e.g.
  `http://localhost:3000/sessions/stream`). Use it in **client** snippets,
  which fetch the resource.
* `'${PATH}'` — the **route path only** (e.g. `/sessions/stream`, including
  any `:param` segments). Use it in **server** snippets, which register the
  route — a server never mounts a handler on a full origin URL.

Outside the marker region the file can use whatever placeholder makes sense
for compilation.

## Why per-language source files?

* Each example lives next to its language's source tree, so it can be wired
  into that language's tooling. Today only the TypeScript snippets are
  typechecked (`pnpm -C playground check-snippets`, run as part of
  `pnpm -C playground build`); the other languages are extracted verbatim
  and not yet compiled, so review them like docs.
* The playground, the API-reference site, and the language READMEs can all
  point at the same canonical example.
* Adding a new language to the playground is one entry in the `ROOTS` map +
  a directory of files. No new tooling.

## Build wire-up

`playground/package.json` runs the extractor in `predev` and `prebuild`:

```jsonc
"scripts": {
  "predev":  "node scripts/gen-snippets.mjs",
  "prebuild":"node scripts/gen-snippets.mjs",
  // …
}
```

Output: `playground/app/src/lib/snippets.gen.json`. The file is committed so
contributors who only touch the playground UI don't need to run the
extractor.
