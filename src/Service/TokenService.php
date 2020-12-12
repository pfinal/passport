<?php

namespace PFinal\Passport\Service;

use Firebase\JWT\JWT;
use PFinal\Passport\Dao\TokenDB;
use PFinal\Passport\Exception\InvalidAccountException;
use PFinal\Passport\Exception\InvalidJwtKeyException;
use PFinal\Passport\Exception\InvalidPasswordException;
use PFinal\Passport\Exception\InvalidTokenException;

/**
 * Token服务
 * @date 2020-12-12
 */
class TokenService
{
    protected $db;

    // user表相关字段
    public static $mobile = 'mobile';
    public static $username = 'username';
    public static $email = 'email';
    public static $passwordHash = 'password_hash';

    // 配置
    public static $passwordHashType = 'md5salt';
    public static $tokenType = 'jwt';
    public static $tokenExpire = 2592000; // 30天

    public function __construct(TokenDB $db)
    {
        $this->db = $db;
    }

    /**
     * 创建token
     *
     * @param $account
     * @param $password
     * @return string
     */
    public function createToken($account, $password)
    {
        // 识别帐号是: 手机|邮箱|用户名，生成查询条件
        $condition = $this->buildQueryCondition($account);

        // 查询用户信息
        $user = $this->db->findUser($condition);

        if ($user == null) {
            throw new InvalidAccountException();
        }

        // 验证密码
        if (!$this->passwordVerify($password, $user[static::$passwordHash], static::$passwordHashType)) {
            throw new InvalidPasswordException();
        }

        return $this->makeToken($user['id'], [], static::$tokenType);
    }

    /**
     * 验证token
     *
     * @param $token
     * @param string $type
     * @return array  ['user_id' => 'xx']
     */
    public function tokenVerify($token, $type = 'jwt')
    {
        if ($type === 'jwt') {
            JWT::$leeway = 60 * 3; // 允许的服务器之间时间差 秒
            try {
                return (array)JWT::decode($token, $this->getJwtKey(), array('HS256'));
            } catch (\Exception $e) {
                // nothing to do
            }

            throw new InvalidTokenException();
        }

        //清理过期的token 概率为0.1%
        if (mt_rand(0, 1000000) < 1000) {
            $time = date('Y-m-d H:i:s', time() - static::$tokenExpire);
            $this->db->deleteExpireToken($time);
        }

        $tokenInfo = $this->db->findToken($token);
        if ($tokenInfo == null) {
            throw new InvalidTokenException();
        }

        //有效期验证
        if (time() - strtotime($tokenInfo['created_at']) > static::$tokenExpire) {
            throw new InvalidTokenException();
        }

        return ['user_id' => (string)$tokenInfo['user_id']];
    }

    /**
     * 删除token
     *
     * @param $token
     * @return bool
     */
    public function tokenDelete($token)
    {
        return $this->db->deleteToken($token);
    }

    /**
     * 生成密码hash
     *
     * @param $password
     * @param string $type
     * @return string
     */
    public function passwordHash($password, $type = 'md5salt')
    {
        switch ($type) {
            case 'php_password_hash':
                return password_hash($password, PASSWORD_DEFAULT);
            case 'md5salt':
            default:
                $salt = substr(md5(uniqid(true)), rand(0, 10), 10);
                return md5($password . $salt) . $salt;
        }
    }

    /**
     * 验证密码
     *
     * @param $password
     * @param $hash
     * @param string $type
     * @return bool
     */
    public function passwordVerify($password, $hash, $type = 'md5salt')
    {
        switch ($type) {
            case 'php_password_hash':
                return password_verify($password, $hash);
            case 'md5salt':
            default:
                $md5 = substr($hash, 0, 32);
                if (strlen($hash > 32)) {
                    $salt = substr($hash, 32);
                } else {
                    $salt = '';
                }
                return md5($password . $salt) === $md5;
        }
    }

    /**
     * 生成token
     *
     * @param $userId
     * @param array $payload
     * @param string $type
     * @return string
     */
    protected function makeToken($userId, array $payload = [], $type = 'jwt')
    {
        if ($type === 'jwt') {
            /*
                iss: jwt签发者
                sub: jwt所面向的用户
                aud: 接收jwt的一方
                exp: jwt的过期时间，这个过期时间必须要大于签发时间
                nbf: 定义在什么时间之前，该jwt都是不可用的
                iat: jwt的签发时间
                jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击
            */

            $now = time();
            $payload += array(
                "iat" => $now,
                "exp" => $now + static::$tokenExpire,
                "user_id" => (string)$userId,
            );

            return JWT::encode($payload, $this->getJwtKey());
        }

        $token = strtolower(str_replace('-', '', static::guid()));
        $this->db->saveToken(['token' => $token, 'user_id' => $userId, 'created_at' => @date('Y-m-d H:i:s')]);

        return $token;
    }

    /**
     * 构建查询条件，将帐号识别为手机号、邮箱或用户名
     *
     * @param $account
     * @return array
     */
    protected function buildQueryCondition($account)
    {
        $mobilePattern = '/^1\d{10}$/';
        if (preg_match($mobilePattern, $account)) {
            return [static::$mobile => $account];
        }

        $emailPattern = '/^[a-zA-Z0-9!#$%&\'*+\\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&\'*+\\/=?^_`{|}~-]+)*@(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$/';
        if (preg_match($emailPattern, $account)) {
            return [static::$email => $account];
        }

        return [static::$username => $account];
    }

    /**
     * 获取jwt的key
     *
     * @return string
     */
    protected function getJwtKey()
    {
        $jwtKey = (string)getenv('JWT_KEY');
        if (empty($jwtKey)) {
            throw new InvalidJwtKeyException();
        }

        return $jwtKey;
    }

    /**
     * 生成全局唯一标识符，类似 09315E33-480F-8635-E780-7A8E61FB49AA
     *
     * @param null $namespace
     * @return string
     */
    protected static function guid($namespace = null)
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
