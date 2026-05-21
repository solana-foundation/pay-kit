<?php

declare(strict_types=1);

if ($argc !== 3) {
    fwrite(STDERR, "usage: php scripts/check_coverage.php <clover.xml> <minimum-percent>\n");
    exit(2);
}

$coverageFile = $argv[1];
$minimum = (float)$argv[2];
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

$coverage = ($covered / $statements) * 100;
printf("PHP coverage: %.2f%% (%d/%d statements)\n", $coverage, $covered, $statements);

if ($coverage + 0.00001 < $minimum) {
    fwrite(STDERR, sprintf("coverage %.2f%% is below required %.2f%%\n", $coverage, $minimum));
    exit(1);
}
