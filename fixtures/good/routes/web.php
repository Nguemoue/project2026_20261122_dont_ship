<?php

use Illuminate\Support\Facades\Route;

Route::get('/orders', [\App\Http\Controllers\OrderController::class, 'index']);

Route::post('/webhook', function () {
    $dice = mt_rand(1, 6);

    return response('ok ' . $dice);
});
