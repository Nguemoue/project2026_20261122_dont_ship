<?php

use Illuminate\Support\Facades\Route;

Route::get('/debug', function () {
    dd($order);
});

Route::middleware('web')->withoutMiddleware(\App\Http\Middleware\VerifyCsrfToken::class);

Route::get('/go', function () {
    header('Location: ' . $_GET['next']);
    return redirect($_GET['next']);
});
