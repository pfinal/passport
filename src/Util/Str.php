<?php
namespace PFinal\Passport\Util;

class Str{

    /**
     * 生成全局唯一标识符，类似 09315E33-480F-8635-E780-7A8E61FB49AA
     *
     * @param null $namespace
     * @return string
     */
    public static function guid($namespace = null)
    {
        static $guid = '';
        $uid = uniqid(mt_rand(), true);

        $data = $namespace;
        $data .= isset($_SERVER['REQUEST_TIME']) ? $_SERVER['REQUEST_TIME'] : time();                 // 请求那一刻的时间戳
        $data .= isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : rand(0, 999999);  // 访问者操作系统信息
        $data .= isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : rand(0, 999999);          // 服务器IP
        $data .= isset($_SERVER['SERVER_PORT']) ? $_SERVER['SERVER_PORT'] : rand(0, 999999);          // 服务器端口号
        $data .= isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : rand(0, 999999);          // 远程IP
        $data .= isset($_SERVER['REMOTE_PORT']) ? $_SERVER['REMOTE_PORT'] : rand(0, 999999);          // 远程端口

        $hash = strtoupper(hash('ripemd128', $uid . $guid . md5($data)));
        $guid = substr($hash, 0, 8) . '-' . substr($hash, 8, 4) . '-' . substr($hash, 12, 4) . '-' . substr($hash, 16, 4) . '-' . substr($hash, 20, 12);

        return $guid;
    }
}