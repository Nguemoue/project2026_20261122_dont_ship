<?php

namespace App\Http\Controllers;

class OrderController
{
    public function index()
    {
        // env('APP_DEBUG') must stay out of here. config('app.debug') survives config:cache.
        $debug = config('app.debug');
        $note = 'Call config(), never env(), once config is cached.';
        $sample = 'whereRaw("status = $status") is documentation, not a query';
        $status = request('status');

        return \DB::table('orders')->whereRaw('status = ?', [$status])->get();
    }
}
