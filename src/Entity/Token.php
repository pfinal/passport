<?php

namespace PFinal\Passport\Entity;

class Token
{
    public $userId;
    public $token;
    public $expireAt;

    public function __construct($userId, $token, $expireAt = 0)
    {
        $this->userId = $userId;
        $this->token = $token;
        $this->expireAt = $expireAt;
    }
}
