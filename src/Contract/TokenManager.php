<?php

namespace WWON\JwtGuard\Contract;

use WWON\JwtGuard\Claim;

/**
 * Interface TokenManager
 *
 * $userId is default to user ID of the users table, however,
 * this can be changed according to the need of the program.
 * Ultimately it is the identifier of user which can be
 * set by overriding function getKeyName on user entity
 *
 * @package App\Services\Auth
 */
interface TokenManager
{

    /**
     * add claim to the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function add(Claim $claim);

    /**
     * check that claim is in the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function check(Claim $claim);

    /**
     * remove claim from the white list
     *
     * @param Claim $claim
     * @return bool
     */
    public function remove(Claim $claim);

    /**
     * remove all claims associate to the subject from the white list
     *
     * @param mixed $userId
     * @return int
     */
    public function removeAll($userId);

}