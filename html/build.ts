import * as esbuild from 'esbuild';
import { writeFileSync, mkdirSync } from 'fs';
import { resolve, dirname } from 'path';

const isTest = process.env.TEST === '1';
const outDir = resolve(import.meta.dirname, 'dist');

mkdirSync(outDir, { recursive: true });

async function buildBundle(
  entryPoint: string,
  outFile: string,
  format: 'iife' | 'esm' = 'iife',
): Promise<string> {
  const result = await esbuild.build({
    entryPoints: [resolve(import.meta.dirname, entryPoint)],
    bundle: true,
    format,
    minify: !isTest,
    sourcemap: isTest ? 'inline' : false,
    write: false,
    target: 'es2022',
    platform: 'browser',
    define: {
      'process.env.NODE_ENV': isTest ? '"development"' : '"production"',
    },
    // Tree-shake unused code
    treeShaking: true,
    // Mark optional peer deps as external — they're dynamically imported
    // and we don't need them (we use @solana/kit, not legacy web3.js)
    external: ['@solana/web3.js'],
  });

  const code = result.outputFiles[0].text;
  const outPath = resolve(outDir, outFile);
  writeFileSync(outPath, code);
  console.log(`  ${outFile} (${(code.length / 1024).toFixed(1)} KB)`);
  return code;
}

/** Write a bundled JS string as a generated file for embedding in server implementations. */
function writeGenerated(code: string, outPath: string, exportName: string): void {
  mkdirSync(dirname(outPath), { recursive: true });
  // Escape backticks and backslashes for template literal embedding
  const escaped = code.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
  writeFileSync(outPath, `// AUTO-GENERATED — do not edit. Run \`npm run build\` in html/ to regenerate.\nexport const ${exportName} = \`${escaped}\`;\n`);
}

async function main() {
  console.log('Building MPP payment link assets...');

  // 1. Build the payment UI (IIFE — inlined in HTML)
  const paymentUIRaw = await buildBundle('src/main.ts', 'payment-ui.js');
  // mppx injects `content` as raw HTML — wrap in <script> tags.
  const paymentUI = `<script>${paymentUIRaw}</script>`;

  // 2. Build the service worker for standalone servers (Rust/Go/Lua)
  const serviceWorker = await buildBundle('src/service-worker.ts', 'service-worker.js');

  // 3. Generate the mppx-based HTML template for standalone servers (Rust/Go/Lua)
  //    Uses mppx's rendering at build time so all servers get the same design.
  // Import mppx internals directly (not re-exported, but stable across 0.5.x)
  const Html = await import('./node_modules/mppx/dist/server/internal/html/config.js');
  const { serviceWorker: serviceWorkerContent } = await import('./node_modules/mppx/dist/server/internal/html/serviceWorker.gen.js');

  const theme = Html.mergeDefined({
    favicon: undefined,
    fontUrl: undefined,
    logo: { dark: 'https://solana.com/src/img/branding/solanaLogoMark.svg', light: 'https://solana.com/src/img/branding/solanaLogoMark.svg' },
    ...Html.defaultTheme,
  }, {});
  const text = Html.sanitizeRecord(Html.mergeDefined(Html.defaultText, {}));

  // Template uses mustache-style placeholders that servers replace at runtime
  const htmlTemplate = Html.html`<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex" />
    <meta name="color-scheme" content="${theme.colorScheme}" />
    <title>${text.title}</title>
    ${Html.favicon(theme, '')} ${Html.font(theme)} ${Html.style(theme)}
  </head>
  <body>
    <main>
      <header class="${Html.classNames.header}">
        ${Html.logo(theme)}
        <span>${text.paymentRequired}</span>
      </header>
      <section class="${Html.classNames.summary}" aria-label="Payment summary">
        <h1 class="${Html.classNames.summaryAmount}">{{AMOUNT}}</h1>
        {{DESCRIPTION}}
        {{EXPIRES}}
      </section>
      <div id="${Html.rootId}" aria-label="Payment form"></div>
      <script id="__MPP_DATA__" type="application/json">{{DATA_JSON}}</script>
      <script>${paymentUIRaw}</script>
    </main>
  </body>
</html>`;

  // Also generate the service worker content from mppx
  const mppxServiceWorker = serviceWorkerContent;

  // Write the shared template + service worker to html/dist/ (canonical location)
  writeFileSync(resolve(outDir, 'template.html'), htmlTemplate);
  writeFileSync(resolve(outDir, 'service-worker.js'), mppxServiceWorker);

  console.log(`  html-template.html (${(htmlTemplate.length / 1024).toFixed(1)} KB)`);

  // 4. Write generated embedding files for each language

  // Rust: write template + service worker for include_str!
  const rustDir = resolve(import.meta.dirname, '..', 'rust', 'src', 'server', 'html');
  mkdirSync(rustDir, { recursive: true });
  writeFileSync(resolve(rustDir, 'template.gen.html'), htmlTemplate);
  writeFileSync(resolve(rustDir, 'service_worker.gen.js'), mppxServiceWorker);
  // Keep raw payment UI for backward compat
  writeFileSync(resolve(rustDir, 'payment_ui.gen.js'), paymentUIRaw);

  // Go: write template + service worker for go:embed
  const goDir = resolve(import.meta.dirname, '..', 'go', 'protocols', 'mpp', 'server', 'html');
  mkdirSync(goDir, { recursive: true });
  writeFileSync(resolve(goDir, 'template.gen.html'), htmlTemplate);
  writeFileSync(resolve(goDir, 'service-worker.gen.js'), mppxServiceWorker);
  writeFileSync(resolve(goDir, 'payment-ui.gen.js'), paymentUIRaw);

  // Lua: write template + service worker as Lua strings
  const luaDir = resolve(import.meta.dirname, '..', 'lua', 'pay_kit', 'protocols', 'mpp', 'server', 'html_assets');
  mkdirSync(luaDir, { recursive: true });
  const luaTemplate = htmlTemplate.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
  const luaSW = mppxServiceWorker.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n');
  writeFileSync(
    resolve(luaDir, 'gen.lua'),
    `-- AUTO-GENERATED — do not edit. Run \`npm run build\` in html/ to regenerate.\nlocal M = {}\nM.html_template = '${luaTemplate}'\nM.service_worker_js = '${luaSW}'\nreturn M\n`,
  );

  // Python: write template + service worker as raw files for importlib.resources
  const pyDir = resolve(import.meta.dirname, '..', 'python', 'src', 'pay_kit', 'protocols', 'mpp', 'server', 'html');
  mkdirSync(pyDir, { recursive: true });
  writeFileSync(resolve(pyDir, 'template.gen.html'), htmlTemplate);
  writeFileSync(resolve(pyDir, 'service_worker.gen.js'), mppxServiceWorker);
  // Ensure __init__.py exists so importlib.resources can find the package
  const pyInitPath = resolve(pyDir, '__init__.py');
  try { writeFileSync(pyInitPath, '', { flag: 'wx' }); } catch { /* already exists */ }

  // TypeScript: write as .gen.ts export for @solana/mpp (with <script> wrapper for mppx)
  const tsDir = resolve(import.meta.dirname, '..', 'typescript', 'packages', 'mpp', 'src', 'server');
  const escaped = paymentUI.replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
  writeFileSync(
    resolve(tsDir, 'html-assets.gen.ts'),
    `// AUTO-GENERATED — do not edit. Run \`npm run build\` in html/ to regenerate.\nexport const PAYMENT_UI_JS = \`${escaped}\`;\n`,
  );

  console.log('Done!');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
