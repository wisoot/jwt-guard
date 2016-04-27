<?php

namespace WWON\JwtGuard;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Contract\TokenManager;

class JwtService
{

    /**
     * @var string
     */
    private $key;

    /**
     * @var TokenManager
     */
    protected $tokenManager;

    /**
     * JwtService constructor
     *
     * @param TokenManager $tokenManager
     */
    public function __construct(TokenManager $tokenManager)
    {
        $this->key = Config::get('jwt.secret');
        $this->tokenManager = $tokenManager;
    }

    /**
     * getTokenForUser method
     *
     * @param Authenticatable $user
     * @return null|string
     */
    public function getTokenForUser(Authenticatable $user)
    {
        $claim = new Claim([
            'sub' => $user->getAuthIdentifier()
        ]);

        return $this->getTokenForClaim($claim);
    }

    /**
     * getUserIdFromToken method
     *
     * @param $token
     * @return mixed|null
     */
    public function getUserIdFromToken($token)
    {
        $claim = $this->getClaimFromToken($token);

        if (!empty($claim) && $this->tokenManager->check($claim)) {
            return $claim->sub;
        }

        return null;
    }

    /**
     * refreshToken method
     *
     * @param $token
     * @return null|string
     */
    public function refreshToken($token)
    {
        $claim = $this->getClaimFromToken($token);

        if (empty($claim)) {
            return null;
        }

        $this->tokenManager->remove($claim);

        $newClaim = new Claim([
            'sub' => $claim->sub
        ]);

        return $this->getTokenForClaim($newClaim);
    }

    /**
     * getTokenForUser method
     *
     * @param Claim $claim
     * @return null|string
     */
    protected function getTokenForClaim(Claim $claim)
    {
        $token = JWT::encode($claim->toArray(), $this->key);
        $this->tokenManager->add($claim);

        return $token;
    }

    /**
     * getClaimFromToken method
     *
     * @param $token
     * @return null|Claim
     */
    protected function getClaimFromToken($token)
    {
        try {
            $payload = JWT::decode($token, $this->key);

            return new Claim((array) $payload);

        } catch (\Exception $e) {}

        return null;
    }

}