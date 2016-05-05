<?php

namespace WWON\JwtGuard\Contract;

use WWON\JwtGuard\Claim;

/**
 * Interface ClaimManager
 *
 * This manager will manage and keep track of claim to in the persisting database
 * and will use that to validate claim
 */
interface ClaimManager
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
     * @param Claim $claim
     * @return int
     */
    public function removeAll(Claim $claim);

}