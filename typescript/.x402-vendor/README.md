# Vendored `@x402` tarballs

These are prebuilt npm tarballs of `@x402/core` and `@x402/svm`, packed from the
**`external/x402` git submodule** (`x402-foundation/x402`, pinned to a specific
commit on `main`). `@solana/pay-kit` depends on them via relative `file:` paths
and **bundles** them into its `dist`, so the published `@solana/pay-kit` carries
no `@x402` dependency and its `@x402` surface is pinned to one reviewed commit
rather than a semver range.

They're committed so `pnpm install --frozen-lockfile` is reproducible in CI and
fresh clones without first building the submodule.

## Regenerating

After the submodule moves (e.g. upstream `main` advances) or its version bumps:

```sh
just x402-vendor      # init submodule, build @x402/core + @x402/svm, repack here
cd typescript && pnpm install   # refresh the lockfile if the tarballs changed
```

If the version changed, update the `file:` references in
`packages/pay-kit/package.json` and the `@x402/core` override in
`package.json` to match the new tarball filenames.
