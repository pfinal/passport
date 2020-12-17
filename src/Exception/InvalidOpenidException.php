<?php

namespace PFinal\Passport\Exception;

class InvalidOpenidException extends \LogicException
{
    public function __construct($message = "openid无效", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}