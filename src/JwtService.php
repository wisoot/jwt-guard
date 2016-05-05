<?php

namespace WWON\JwtGuard;

use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Contract\ClaimManager as ClaimManagerContract;
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
     * @var ClaimManagerContract
     */
    protected $claimManager;

    /**
     * JwtService constructor
     *
     * @param ClaimManagerContract $claimManager
     */
    public function __construct(ClaimManagerContract $claimManager)
    {
        $this->key = Config::get('jwt.secret');
        $this->claimManager = $claimManager;

        JWT::$leeway = Config::get('jwt.leeway');
    }

    /**
     * getTokenForUser method
     *
     * @param Claim $claim
     * @return string
     */
    public function getTokenForClaim(Claim $claim)
    {
        $token = JWT::encode($claim->toArray(), $this->key, Config::get('jwt.algo'));
        $this->claimManager->add($claim);

        return $token;
    }

    /**
     * getEntityFromToken method
     *
     * @param string $token
     * @return Claim
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     */
    public function getClaimFromToken($token)
    {
        $claim = $this->getValidClaimFromToken($token);

        $claim->validateAccessible();

        return $claim;
    }

    /**
     * refreshToken method
     *
     * @param string $token
     * @return string
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     * @throws UnRefreshableException
     */
    public function refreshToken($token)
    {
        $claim = $this->getValidClaimFromToken($token);
        
        if (empty($claim->refresh)) {
            throw new UnRefreshableException;
        }

        $this->claimManager->remove($claim);

        $newClaim = new Claim([
            'sub' => $claim->sub,
            'aud' => $claim->aud,
            'refresh' => $claim->refresh
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

        $this->claimManager->remove($claim);
    }

    /**
     * wipeUserTokens method
     *
     * @param Claim $claim
     */
    public function wipeUserTokens(Claim $claim)
    {
        $this->claimManager->removeAll($claim);
    }

    /**
     * getValidClaimFromToken method
     *
     * @param $token
     * @return Claim
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     */
    protected function getValidClaimFromToken($token)
    {
        try {
            $payload = JWT::decode($token, $this->key, [
                'HS256', 'HS384', 'HS512', 'RS256'
            ]);

        } catch (ExpiredException $e) {
            throw new TokenExpiredException($e->getMessage(), $e->getCode(), $e);
        }

        $claim = new Claim((array) $payload);

        if (!$this->claimManager->check($claim)) {
            throw new InvalidTokenException;
        }

        return $claim;
    }

}