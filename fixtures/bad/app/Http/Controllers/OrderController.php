<?php

namespace App\Http\Controllers;

class OrderController
{
    public function show(): mixed
    {
        $key = env('STRIPE_SECRET');

        return $key;
    }
}
