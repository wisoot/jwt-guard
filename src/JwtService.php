<?php

namespace WWON\JwtGuard;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Contract\TokenManager;
use WWON\JwtGuard\Exceptions\InaccessibleException;
use WWON\JwtGuard\Exceptions\InvalidTokenException;
use WWON\JwtGuard\Exceptions\MalformedException;
use WWON\JwtGuard\Exceptions\TokenExpiredException;
use WWON\JwtGuard\Exceptions\UnRefreshableException;

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
            'sub' => $user->getAuthIdentifier(),
            'refresh' => $refreshable
        ]);

        return $this->getTokenForClaim($claim);
    }

    /**
     * getUserIdFromToken method
     *
     * @param string $token
     * @return mixed
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     */
    public function getUserIdFromToken($token)
    {
        $claim = $this->getClaimFromToken($token);

        $claim->validateAccessible();

        if (!$this->tokenManager->check($claim)) {
            throw new InvalidTokenException;
        }

        return $claim->sub;
    }

    /**
     * refreshToken method
     *
     * @param string $token
     * @return string
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws UnRefreshableException
     */
    public function refreshToken($token)
    {
        $claim = $this->getClaimFromToken($token);
        
        if (empty($claim->refresh)) {
            throw new UnRefreshableException;
        }

        $this->tokenManager->remove($claim);

        $newClaim = new Claim([
            'sub' => $claim->sub,
            'refresh' => true
        ]);

        return $this->getTokenForClaim($newClaim);
    }

    /**
     * invalidateToken method
     *
     * @param string $token
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws UnRefreshableException
     */
    public function invalidateToken($token)
    {
        $claim = $this->getClaimFromToken($token);

        $this->tokenManager->remove($claim);
    }

    /**
     * wipeUserTokens method
     *
     * @param Authenticatable $user
     */
    public function wipeUserTokens(Authenticatable $user)
    {
        $this->tokenManager->removeAll($user->getAuthIdentifier());
    }

    /**
     * getTokenForUser method
     *
     * @param Claim $claim
     * @return string
     */
    protected function getTokenForClaim(Claim $claim)
    {
        $token = JWT::encode($claim->toArray(), $this->key, Config::get('jwt.algo'));
        $this->tokenManager->add($claim);

        return $token;
    }

    /**
     * getClaimFromToken method
     *
     * @param $token
     * @return Claim
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    protected function getClaimFromToken($token)
    {
        try {
            $payload = JWT::decode($token, $this->key, [
                'HS256', 'HS384', 'HS512', 'RS256'
            ]);

        } catch (ExpiredException $e) {
            throw new TokenExpiredException($e->getMessage(), $e->getCode(), $e);
        }

        return new Claim((array) $payload);
    }

}