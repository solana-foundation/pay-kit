<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/x402/InteropServer.php';

use const SolanaMpp\X402\Interop\CAPABILITY_PAYLOAD;
use const SolanaMpp\X402\Interop\DEFAULT_RESOURCE_PATH;
use function SolanaMpp\X402\Interop\response_for;
use function SolanaMpp\X402\Interop\state_from_env;

$server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "failed to bind PHP interop server: {$errstr}\n");
    exit(1);
}

$address = stream_socket_get_name($server, false);
if ($address === false) {
    fwrite(STDERR, "failed to read PHP interop server address\n");
    exit(1);
}

$state = null;
$stateForPath = static function (string $path) use (&$state): ?array {
    if (!in_array($path, ['/exact', DEFAULT_RESOURCE_PATH], true)) {
        return null;
    }

    $state ??= state_from_env(getenv());
    return $state;
};

$port = (int) substr(strrchr($address, ':'), 1);
echo json_encode([
    'type' => 'ready',
    'port' => $port,
] + CAPABILITY_PAYLOAD, JSON_THROW_ON_ERROR) . PHP_EOL;

$running = true;
if (function_exists('pcntl_signal')) {
    pcntl_signal(SIGTERM, static function () use (&$running): void {
        $running = false;
    });
    pcntl_signal(SIGINT, static function () use (&$running): void {
        $running = false;
    });
}

while ($running) {
    if (function_exists('pcntl_signal_dispatch')) {
        pcntl_signal_dispatch();
    }

    $connection = @stream_socket_accept($server, 1);
    if ($connection === false) {
        continue;
    }

    $requestLine = fgets($connection) ?: '';
    $path = '/';
    if (preg_match('/^[A-Z]+\s+([^\s]+)\s+HTTP\/[0-9.]+$/', trim($requestLine), $matches) === 1) {
        $path = parse_url($matches[1], PHP_URL_PATH) ?: '/';
    }

    $headers = [];
    while (($line = fgets($connection)) !== false) {
        if (trim($line) === '') {
            break;
        }
        if (str_contains($line, ':')) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }
    }

    [$status, $responseHeaders, $body] = response_for($path, $headers, $stateForPath($path));
    $encoded = json_encode($body, JSON_THROW_ON_ERROR);
    $reason = match ($status) {
        200 => 'OK',
        402 => 'Payment Required',
        404 => 'Not Found',
        default => 'Not Implemented',
    };
    $headerLines = '';
    foreach ($responseHeaders as $name => $value) {
        $headerLines .= "{$name}: {$value}\r\n";
    }

    fwrite(
        $connection,
        "HTTP/1.1 {$status} {$reason}\r\n" .
        "content-type: application/json\r\n" .
        $headerLines .
        'content-length: ' . strlen($encoded) . "\r\n" .
        "connection: close\r\n\r\n" .
        $encoded,
    );
    fclose($connection);
}

fclose($server);
