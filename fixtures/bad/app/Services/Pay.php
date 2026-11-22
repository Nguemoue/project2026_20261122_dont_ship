<?php

namespace App\Services;

class Pay
{
    public function charge(string $password, string $cmd, string $status): void
    {
        $hash = md5($password);
        shell_exec($cmd);
        $payload = unserialize($_POST['payload']);
        \DB::table('orders')->whereRaw("status = '$status'")->get();
        $otp = mt_rand(100000, 999999);
        \Illuminate\Support\Facades\Http::withoutVerifying()->post('https://pay.example');
        header('Access-Control-Allow-Origin: *');
        ini_set('display_errors', '1');
        phpinfo();
        unset($hash, $payload, $otp);
    }
}
