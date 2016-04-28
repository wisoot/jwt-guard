<?php

namespace WWON\JwtGuard;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Contract\TokenManager;
use WWON\JwtGuard\Exceptions\InaccessibleException;
use WWON\JwtGuard\Exceptions\MalformedException;
use WWON\JwtGuard\Exceptions\TokenExpiredException;

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

        JWT::$leeway = Config::get('jwt.leeway');
    }

    /**
     * getTokenForUser method
     *
     * @param Authenticatable $user
     * @param bool $refreshable
     * @return string
     */
    public function getTokenForUser(Authenticatable $user, $refreshable = false)
    {
        $claim = new Claim([
            'sub' => $user->getAuthIdentifier()
        ]);

        if ($refreshable) {
            $claim->exp = Config::get('jwt.refresh_ttl') * 60;
        }

        return $this->getTokenForClaim($claim);
    }

    /**
     * getUserIdFromToken method
     *
     * @param $token
     * @return mixed
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    public function getUserIdFromToken($token)
    {
        $claim = $this->getClaimFromToken($token);

        if (!$this->tokenManager->check($claim)) {
            return $claim->sub;
        }

        return $claim->sub;
    }

    /**
     * refreshToken method
     *
     * @param $token
     * @return string
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    public function refreshToken($token)
    {
        $claim = $this->getClaimFromToken($token);

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
     * @return string
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
     * @return Claim
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    protected function getClaimFromToken($token)
    {
        try {
            $payload = JWT::decode($token, $this->key);

        } catch (ExpiredException $e) {
            throw new TokenExpiredException($e->getMessage(), $e->getCode(), $e);
        }

        return new Claim((array) $payload);
    }

}