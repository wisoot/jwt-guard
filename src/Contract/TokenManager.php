<?php

namespace WWON\JwtGuard\Contract;

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
     * add token to the given user ID
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function add($userId, $token);

    /**
     * check that user has this token attached to it
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function check($userId, $token);

    /**
     * remove the given token for the given user ID
     *
     * @param mixed $userId
     * @param string $token
     * @return bool
     */
    public function remove($userId, $token);

}