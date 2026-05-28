<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;

// Dual-protocol example: the `paykit:<name>` route middleware
// resolves the handle against the `App\Pricing` instance the
// service container auto-wires. Each route accepts both x402 and
// MPP by default; the active protocol is picked per request from
// the client's Authorization / Payment-Signature header.

Route::get('/paid', fn () => response()->json(['ok' => true, 'paid' => true]))
    ->middleware('paykit:paid');

Route::get('/api/data', fn () => response()->json(['data' => []]))
    ->middleware('paykit:x402Only');

Route::post('/marketplace/buy', fn () => response()->json(['sold' => true]))
    ->middleware('paykit:marketplaceSale');
