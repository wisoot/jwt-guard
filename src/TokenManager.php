<?php

namespace WWON\JwtGuard;

use Carbon\Carbon;

class TokenManager implements Contract\TokenManager
{

    /**
     * @var string
     */
    protected $tokenTable;

    /**
     * @var string
     */
    protected $userForeignKey;

    /**
     * TokenManager constructor
     */
    public function __construct()
    {
        $this->tokenTable = \Config::get('jwt_guard.token_table');
        $this->userForeignKey = \Config::get('jwt_guard.user_foreign_key');
    }

    /**
     * add token to the given user ID
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function add($userId, $token)
    {
        if ($this->check($userId, $token)) {
            return;
        }

        \DB::table($this->tokenTable)->insert([
            $this->userForeignKey => $userId,
            'token' => $token,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString()
        ]);
    }

    /**
     * check that user has this token attached to it
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function check($userId, $token)
    {
        $token = \DB::table($this->tokenTable)
            ->where($this->userForeignKey, $userId)
            ->where('token', $token)->first();

        return !empty($token);
    }

    /**
     * remove the given token for the given user ID
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function remove($userId, $token)
    {
        if (!$this->check($userId, $token)) {
            return false;
        }

        \DB::table($this->tokenTable)
            ->where($this->userForeignKey, $userId)
            ->where('token', $token)->delete();

        return true;
    }
}