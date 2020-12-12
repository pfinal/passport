<?php

namespace PFinal\Passport\Exception;

class InvalidJwtKeyException extends \LogicException
{
    public function __construct($message = "Jwt配置信息无效", $code = 0, $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}