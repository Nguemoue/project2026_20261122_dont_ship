<?php

namespace App\Services;

class Signer
{
    public function sign(string $payload, string $secret): string
    {
        return hash('sha256', $payload . $secret);
    }

    public function store(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }
}
