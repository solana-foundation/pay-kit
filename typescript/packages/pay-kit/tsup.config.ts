import { defineConfig } from 'tsup';

// @x402/core + @x402/svm are a fork (built from the external/x402 submodule)
// that isn't published to npm under those names, so we bundle them into the
// dist and the published package carries no @x402 dependency. `zod` is bundled
// alongside them — @x402/core's only non-Solana runtime dep — so pay-kit
// doesn't add a top-level zod that would clash with mppx's bundled zod.
//
// @solana/mpp (and its /server, /client subpaths) is also bundled in, so the
// published package is self-contained: it carries no @solana/mpp dependency and
// can be published without @solana/mpp being on npm first (no publish ordering).
// @solana/mpp is still published standalone for callers who want its surface
// directly; pay-kit just embeds the copy it was built against. The
// @solana-program/* deps and the @solana/kit / mppx peers stay external and
// resolve from the consumer's install.
export default defineConfig({
    clean: true,
    dts: true,
    entry: {
        index: 'src/index.ts',
        'client/index': 'src/client/index.ts',
    },
    format: ['esm'],
    noExternal: [/^@x402\//, 'zod', /^@solana\/mpp(\/|$)/],
    sourcemap: true,
    target: 'es2022',
});
