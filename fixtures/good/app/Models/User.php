<?php

namespace App\Models;

class User
{
    protected $fillable = ['name', 'email'];

    protected $guarded = ['password', 'remember_token'];
}
