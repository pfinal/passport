<?php

namespace PFinal\Passport\Exception;

class InvalidTokenException extends \LogicException
{
    public function __construct($message = "Token无效", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
