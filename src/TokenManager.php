<?php

namespace WWON\JwtGuard;

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

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
        $this->tokenTable = Config::get('jwt.token_table');
        $this->userForeignKey = Config::get('jwt.user_foreign_key');
    }

    /**
     * add claim to the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function add(Claim $claim)
    {
        if ($this->check($claim)) {
            return;
        }

        DB::table($this->tokenTable)->insert([
            $this->userForeignKey => $claim->sub,
            'token' => $claim->jti,
            'created_at' => Carbon::now()->toDateTimeString(),
            'updated_at' => Carbon::now()->toDateTimeString()
        ]);
    }

    /**
     * check that claim is in the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function check(Claim $claim)
    {
        $token = DB::table($this->tokenTable)
            ->where($this->userForeignKey, $claim->sub)
            ->where('token', $claim->jti)->first();

        return !empty($token);
    }

    /**
     * remove claim from the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function remove(Claim $claim)
    {
        if (!$this->check($claim)) {
            return false;
        }

        DB::table($this->tokenTable)
            ->where($this->userForeignKey, $claim->sub)
            ->where('token', $claim->jti)->delete();

        return true;
    }

    /**
     * remove all claims associate to the subject from the white list
     *
     * @param mixed $userId
     * @return int
     */
    public function removeAll($userId)
    {
        return DB::table($this->tokenTable)
            ->where($this->userForeignKey, $userId)
            ->delete();
    }

}