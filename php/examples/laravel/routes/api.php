<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;

Route::get('/paid', function () {
    return response()->json(['ok' => true, 'paid' => true]);
})->middleware('mpp.charge');
