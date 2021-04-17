<?php

namespace PFinal\Passport\Service;

use Firebase\JWT\JWT;
use PFinal\Passport\Dao\Store;
use PFinal\Passport\Entity\Token;
use PFinal\Passport\Exception\InvalidAccountException;
use PFinal\Passport\Exception\InvalidJwtKeyException;
use PFinal\Passport\Exception\InvalidPasswordException;
use PFinal\Passport\Exception\InvalidTokenException;
use PFinal\Passport\Exception\InvalidOpenidException;
use PFinal\Passport\Util\Str;

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
    public static $changePasswordAt = 'change_password_at'; // yyyy-mm-dd hh:ii:ss

    // 配置
    public static $passwordHashType = 'md5salt'; // md5salt|php_password_hash
    public static $tokenType = 'jwt';  // jwt|store
    public static $tokenExpire = 2592000; // 30天

    public function __construct(Store $db)
    {
        $this->db = $db;
    }

    /**
     * 创建token
     *
     * @param $account
     * @param $password
     * @return Token
     */
    public function tokenCreateByAccount($account, $password)
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

        return $this->tokenCreate($user['id'], [], static::$tokenType);
    }

    /**
     * 创建token
     *
     * @param $platform
     * @param $appid
     * @param $openid
     *
     * @return Token
     */
    public function tokenCreateByOpenid($platform, $appid, $openid)
    {
        // 查询用户信息
        $userId = $this->db->findUserIdByOpenid($platform, $appid, $openid);

        if ($userId == null) {
            throw new InvalidOpenidException();
        }

        return $this->tokenCreate($userId, [], static::$tokenType);
    }

    /**
     * 验证token
     *
     * @param $token
     * @param string $type
     * @param bool $checkChangePasswordTime 是否检查修改密码的时间
     * @return Token
     */
    public function tokenVerify($token, $type = 'jwt', $checkChangePasswordTime = false)
    {
        if ($type === 'jwt') {
            JWT::$leeway = 60 * 3; // 允许的服务器之间时间差 秒
            try {
                $info = (array)JWT::decode($token, $this->getJwtKey(), array('HS256'));

                if ($checkChangePasswordTime) {
                    $user = $this->db->findUser(['id' => $info['user_id']]);

                    // 如果token签发时间早于最近一次修改密码的时间，则token无效
                    if (strtotime($user[static::$changePasswordAt]) > $info['iat']) {
                        throw new InvalidTokenException();
                    }
                }

                return new Token($info['user_id'], $token);
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

        return new Token($tokenInfo['user_id'], $token);
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
                return password_hash($password, PASSWORD_BCRYPT);
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
     * @return Token
     */
    public function tokenCreate($userId, array $payload = [], $type = 'jwt')
    {
        $now = time();
        $exp = $now + static::$tokenExpire;

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

            $payload += array(
                "iat" => $now,
                "exp" => $exp,
                "user_id" => (string)$userId,
            );

            return new Token($userId, JWT::encode($payload, $this->getJwtKey()), $exp);
        }

        $token = strtolower(str_replace('-', '', Str::guid()));
        $this->db->saveToken(['token' => $token, 'user_id' => $userId, 'created_at' => @date('Y-m-d H:i:s')]);

        return new Token($userId, $token, $exp);
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

}
