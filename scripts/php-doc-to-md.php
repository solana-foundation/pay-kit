<?php
/**
 * php-doc-to-md — walk src/ and emit one .md per class/interface/trait,
 * pulling the docblock summary, method signatures, and parameter docs.
 *
 * phpDocumentor itself ships only HTML templates; the abandoned third-party
 * markdown templates (cebe/phpdoc-md, clean-phpdoc-md) are unmaintained.
 * Instead of pinning to one, we walk the source tree directly with PHP's
 * tokenizer + a small docblock parser. No composer dep.
 *
 * Usage:
 *   php scripts/php-doc-to-md.php <out-dir> <src-root> [<src-root> ...]
 *
 * Invoked from `just docs-php`.
 */

if ($argc < 3) {
    fwrite(STDERR, "usage: php scripts/php-doc-to-md.php <out-dir> <src-root> [<src-root> ...]\n");
    exit(2);
}

$outDir = $argv[1];
$roots = array_slice($argv, 2);

if (!is_dir($outDir)) {
    if (!mkdir($outDir, 0o755, true) && !is_dir($outDir)) {
        fwrite(STDERR, "could not create $outDir\n");
        exit(1);
    }
}

/**
 * Walk a directory tree and return every .php file under it.
 *
 * @return list<string>
 */
function listPhpFiles(string $root): array
{
    $out = [];
    $iter = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );
    foreach ($iter as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $out[] = $file->getPathname();
        }
    }
    sort($out);
    return $out;
}

/**
 * Trim a docblock to its visible lines.
 *
 * @return array{summary: string, description: string, params: array<string, string>, return: string}
 */
function parseDocblock(?string $raw): array
{
    if ($raw === null) {
        return ['summary' => '', 'description' => '', 'params' => [], 'return' => ''];
    }

    $lines = preg_replace('/^\s*\/\*\*|\s*\*\/\s*$/', '', $raw);
    $lines = preg_replace('/^[ \t]*\*\s?/m', '', $lines);
    $body = explode("\n", trim($lines));

    $summary = '';
    $description = [];
    $params = [];
    $return = '';
    $mode = 'summary';

    foreach ($body as $line) {
        $line = rtrim($line);
        if (preg_match('/^@param\s+\S+\s+\$?(\S+)\s*(.*)$/', $line, $m)) {
            $params[$m[1]] = $m[2];
            continue;
        }
        if (preg_match('/^@return\s+\S+\s*(.*)$/', $line, $m)) {
            $return = $m[1];
            continue;
        }
        if (str_starts_with($line, '@')) {
            continue;
        }
        if ($mode === 'summary') {
            if ($line === '') {
                if ($summary !== '') $mode = 'description';
                continue;
            }
            $summary = $summary === '' ? $line : ($summary . ' ' . $line);
            continue;
        }
        $description[] = $line;
    }

    return [
        'summary' => trim($summary),
        'description' => trim(implode("\n", $description)),
        'params' => $params,
        'return' => trim($return),
    ];
}

/**
 * Render one class/interface/trait reflection into markdown.
 */
function renderClass(ReflectionClass $cls): string
{
    $doc = parseDocblock($cls->getDocComment() ?: null);
    $kind = $cls->isInterface() ? 'Interface' : ($cls->isTrait() ? 'Trait' : ($cls->isAbstract() ? 'Abstract class' : 'Class'));

    $out = "# `{$cls->getName()}`\n\n";
    $out .= "_{$kind}_\n\n";
    if ($doc['summary'] !== '') $out .= "$doc[summary]\n\n";
    if ($doc['description'] !== '') $out .= "$doc[description]\n\n";

    $methods = array_filter(
        $cls->getMethods(ReflectionMethod::IS_PUBLIC),
        fn(ReflectionMethod $m) => $m->getDeclaringClass()->getName() === $cls->getName(),
    );
    if ($methods) {
        $out .= "## Methods\n\n";
        usort($methods, fn($a, $b) => strcmp($a->getName(), $b->getName()));
        foreach ($methods as $m) {
            $mdoc = parseDocblock($m->getDocComment() ?: null);
            $params = [];
            foreach ($m->getParameters() as $p) {
                $type = $p->hasType() ? ((string) $p->getType()) . ' ' : '';
                $default = $p->isDefaultValueAvailable()
                    ? ' = ' . var_export($p->getDefaultValue(), true)
                    : '';
                $params[] = "{$type}\${$p->getName()}{$default}";
            }
            $ret = $m->hasReturnType() ? ': ' . ((string) $m->getReturnType()) : '';
            $sig = sprintf(
                "%s%sfunction %s(%s)%s",
                $m->isStatic() ? 'static ' : '',
                'public ',
                $m->getName(),
                implode(', ', $params),
                $ret,
            );
            $out .= "### `{$m->getName()}`\n\n";
            $out .= "```php\n{$sig}\n```\n\n";
            if ($mdoc['summary'] !== '') $out .= "{$mdoc['summary']}\n\n";
            if ($mdoc['params']) {
                $out .= "**Parameters**\n\n";
                foreach ($mdoc['params'] as $name => $desc) {
                    $out .= "- `\${$name}` — " . ($desc ?: '—') . "\n";
                }
                $out .= "\n";
            }
            if ($mdoc['return'] !== '') {
                $out .= "**Returns**: {$mdoc['return']}\n\n";
            }
        }
    }

    return $out;
}

// ── Parse each .php file via tokens to find top-level classes ──

$classes = [];
foreach ($roots as $root) {
    foreach (listPhpFiles($root) as $file) {
        $tokens = token_get_all(file_get_contents($file));
        $ns = '';
        for ($i = 0, $n = count($tokens); $i < $n; $i++) {
            $tok = $tokens[$i];
            if (!is_array($tok)) continue;
            if ($tok[0] === T_NAMESPACE) {
                $j = $i + 1;
                $name = '';
                while ($j < $n && (is_array($tokens[$j]) || $tokens[$j] !== ';')) {
                    if (is_array($tokens[$j]) && $tokens[$j][0] === T_STRING) {
                        $name .= ($name ? '\\' : '') . $tokens[$j][1];
                    } elseif (is_array($tokens[$j]) && $tokens[$j][0] === T_NAME_QUALIFIED) {
                        $name = $tokens[$j][1];
                    }
                    $j++;
                }
                $ns = $name;
            }
            if (in_array($tok[0], [T_CLASS, T_INTERFACE, T_TRAIT], true)) {
                // Skip anonymous classes (preceded by `new`)
                $k = $i - 1;
                while ($k >= 0 && is_array($tokens[$k]) && in_array($tokens[$k][0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                    $k--;
                }
                if ($k >= 0 && is_array($tokens[$k]) && $tokens[$k][0] === T_NEW) continue;

                $j = $i + 1;
                while ($j < $n && is_array($tokens[$j]) && $tokens[$j][0] !== T_STRING) $j++;
                if (isset($tokens[$j]) && is_array($tokens[$j])) {
                    $short = $tokens[$j][1];
                    $classes[] = $ns ? "{$ns}\\{$short}" : $short;
                }
            }
        }
        require_once $file;
    }
}

// ── Reflect + render ──

$index = "# PHP API reference\n\n";
$index .= "Generated from `src/` via PHP's tokenizer + Reflection. One file per class/interface/trait.\n\n";
$index .= "| Class | Kind | Summary |\n|-------|------|---------|\n";

$rendered = 0;
foreach (array_unique($classes) as $fqcn) {
    try {
        $ref = new ReflectionClass($fqcn);
    } catch (Throwable $e) {
        continue;
    }
    $slug = str_replace('\\', '_', $fqcn);
    $path = "$outDir/{$slug}.md";
    file_put_contents($path, renderClass($ref));

    $doc = parseDocblock($ref->getDocComment() ?: null);
    $summary = $doc['summary'] ?: '—';
    $summary = str_replace('|', '\\|', $summary);
    $kind = $ref->isInterface() ? 'interface' : ($ref->isTrait() ? 'trait' : 'class');
    $index .= "| [`$fqcn`](./{$slug}.md) | $kind | $summary |\n";
    $rendered++;
}

$index .= "\n_Regenerate with_ `just docs-php`.\n";
file_put_contents("$outDir/README.md", $index);
fwrite(STDOUT, "Wrote $rendered class doc(s) + index to $outDir\n");
