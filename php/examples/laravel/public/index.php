<?php

declare(strict_types=1);

// solana-php's CurlHttpClient still calls the no-op-since-PHP-8.0 curl_close()
// which raises E_DEPRECATED on PHP 8.5+. Route deprecations to stderr so they
// don't pollute the HTTP response body.
error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

use Illuminate\Foundation\Application;
use Illuminate\Http\Request;

define('LARAVEL_START', microtime(true));

require __DIR__ . '/../vendor/autoload.php';

/** @var Application $app */
$app = require_once __DIR__ . '/../bootstrap/app.php';

$app->handleRequest(Request::capture());
