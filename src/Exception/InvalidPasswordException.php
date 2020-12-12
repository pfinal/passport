<?php

namespace PFinal\Passport\Exception;

class InvalidPasswordException extends \LogicException
{
    public function __construct($message = "帐号与密码不匹配", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
