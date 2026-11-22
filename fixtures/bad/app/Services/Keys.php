<?php

namespace App\Services;

class Keys
{
    public function aws(): string
    {
        // Official documentation sample, not a live credential.
        return 'AKIAIOSFODNN7EXAMPLE';
    }

    public function database(): string
    {
        $dbPassword = 'hunter2hunter2';

        return $dbPassword;
    }
}
