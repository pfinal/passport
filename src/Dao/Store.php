<?php

namespace PFinal\Passport\Dao;

interface Store
{
    /**
     * 查询用户
     * @param array $condition
     * @return array|null
     */
    public function findUser(array $condition);

    /**
     * 保存token
     *
     * @param array $tokenData
     */
    public function saveToken(array $tokenData);

    /**
     * 查询Token信息
     * @param string $token
     * @return array|null
     */
    public function findToken($token);

    /**
     * 删除token
     * @param string $token
     * @return bool
     */
    public function deleteToken($token);

    /**
     * 删除过期token
     * @param string $time
     * @return int
     */
    public function deleteExpireToken($time);

    /**
     * 根据Openid查询用户Id
     *
     * @param $platform
     * @param $appid
     * @param $openid
     * @return string|null
     */
    public function findUserIdByOpenid($platform, $appid, $openid);
}