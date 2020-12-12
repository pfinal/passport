<?php

namespace PFinal\Passport\Dao;

use Leaf\DB;

class LeafStore implements Store
{
    /**
     * 查询用户
     * @param array $condition
     * @return array|null
     */
    public function findUser(array $condition)
    {
        return DB::table('user')->where($condition)->findOne();
    }

    /**
     * 保存token
     *
     * @param array $tokenData
     */
    public function saveToken(array $tokenData)
    {
        DB::table('token')->insert($tokenData);
    }

    /**
     * 查询Token信息
     * @param array $token
     * @return array|null
     */
    public function findToken(array $token)
    {
        return DB::table('token')->where(['token' => $token])->findOne();
    }

    /**
     * 删除token
     * @param string $token
     * @return bool
     */
    public function deleteToken($token)
    {
        return DB::table('token')->where(['token' => $token])->delete() == 1;
    }

    /**
     * 删除过期token
     * @param string $time
     * @return int
     */
    public function deleteExpireToken($time)
    {
        return DB::table('token')->where("created_at<?", [$time])->delete();
    }
}