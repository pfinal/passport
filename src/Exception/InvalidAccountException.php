<?php

namespace PFinal\Passport\Exception;

class InvalidAccountException extends \LogicException
{
    public function __construct($message = "帐号不存在", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}