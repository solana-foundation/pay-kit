<?php

declare(strict_types=1);

if ($argc !== 3) {
    fwrite(STDERR, "usage: php scripts/update_coverage_badge.php <clover.xml> <readme.md>\n");
    exit(2);
}

[$_, $coverageFile, $readmePath] = $argv;
$xml = simplexml_load_file($coverageFile);
if ($xml === false) {
    fwrite(STDERR, "failed to read coverage file: {$coverageFile}\n");
    exit(2);
}

$metrics = $xml->project->metrics;
$covered = (int)$metrics['coveredstatements'];
$statements = (int)$metrics['statements'];
if ($statements === 0) {
    fwrite(STDERR, "coverage file has no statements\n");
    exit(2);
}

$percent = (int)floor(($covered / $statements) * 100);
$color = match (true) {
    $percent >= 90 => 'brightgreen',
    $percent >= 80 => 'green',
    $percent >= 70 => 'yellowgreen',
    $percent >= 60 => 'yellow',
    $percent >= 50 => 'orange',
    default => 'red',
};

$readme = file_get_contents($readmePath);
if ($readme === false) {
    fwrite(STDERR, "failed to read README: {$readmePath}\n");
    exit(2);
}

$pattern = '~https://img\.shields\.io/badge/coverage-[0-9.]+%25-[a-z]+~';
$replacement = "https://img.shields.io/badge/coverage-{$percent}%25-{$color}";
$updated = preg_replace($pattern, $replacement, $readme, -1, $count);
if ($updated === null || !is_string($updated)) {
    fwrite(STDERR, "preg_replace failed against README badge\n");
    exit(2);
}
if ($count === 0) {
    fwrite(STDERR, "no coverage badge found in {$readmePath}\n");
    exit(1);
}

if ($updated === $readme) {
    printf("Coverage badge already at %d%% (%s). No change.\n", $percent, $color);
    exit(0);
}

if (file_put_contents($readmePath, $updated) === false) {
    fwrite(STDERR, "failed to write README: {$readmePath}\n");
    exit(2);
}

printf("Updated coverage badge: %d%% (%s)\n", $percent, $color);
