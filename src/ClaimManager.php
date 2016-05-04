<?php

namespace WWON\JwtGuard;

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

class ClaimManager implements Contract\ClaimManager
{

    /**
     * @var string
     */
    protected $tableName;

    /**
     * @var string
     */
    protected $foreignKey;

    /**
     * TokenManager constructor
     */
    public function __construct()
    {
        $this->tableName = Config::get('jwt.claim_table_name');
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

        DB::table($this->tableName)->insert([
            'subject' => $claim->sub,
            'audience' => $claim->aud,
            'jwt_id' => $claim->jti,
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
        $token = DB::table($this->tableName)
            ->where('audience', $claim->aud)
            ->where('subject', $claim->sub)
            ->where('jwt_id', $claim->jti)->first();

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

        DB::table($this->tableName)
            ->where('audience', $claim->aud)
            ->where('subject', $claim->sub)
            ->where('jwt_id', $claim->jti)->delete();

        return true;
    }

    /**
     * remove all claims associate to the subject from the white list
     *
     * @param Claim $claim
     * @return int
     */
    public function removeAll(Claim $claim)
    {
        return DB::table($this->tableName)
            ->where('audience', $claim->aud)
            ->where('subject', $claim->sub)
            ->delete();
    }

}