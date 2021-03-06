<?php

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Claim;
use WWON\JwtGuard\Contract\ClaimManager;
use WWON\JwtGuard\JwtService;

class JwtServiceTest extends PHPUnit_Framework_TestCase
{

    /**
     * @var Mockery\MockInterface
     */
    private $claimManager;
    
    /**
     * @var JwtService
     */
    private $jwtService;

    /**
     * setUp method
     */
    public function setUp()
    {
        parent::setUp();

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.secret')
            ->andReturn('abcdefg');

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        $this->claimManager = Mockery::mock(ClaimManager::class);
        $this->jwtService = new JwtService($this->claimManager);
    }

    /**
     * tearDown method
     */
    public function tearDown()
    {
        unset($this->jwtService);

        parent::tearDown();
    }

    /**
     * testGetTokenForClaim method
     */
    public function testGetTokenForClaim()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken();

        $items = explode('.', $token);
        $claimBody = json_decode(base64_decode($items[1]));

        $this->assertEquals('http://www.test.com', $claimBody->iss);
        $this->assertEquals($now, $claimBody->iat);
        $this->assertEquals($now + 6000, $claimBody->exp);
        $this->assertEquals($now + 6000, $claimBody->nat);
    }

    /**
     * testGetClaimFromToken method
     */
    public function testGetClaimFromToken()
    {
        $token = $this->getToken();

        $this->claimManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $claim = $this->jwtService->getClaimFromToken($token);

        $this->assertEquals(5, $claim->sub);
        $this->assertEquals('User', $claim->aud);
        $this->assertEquals('http://www.test.com', $claim->iss);
    }

    /**
     * testGetUserIdFromTokenWithInvalidClaim method
     */
    public function testGetUserIdFromTokenWithInvalidClaim()
    {
        $token = $this->getToken();

        $this->claimManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(false);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\InvalidTokenException::class);

        $claim = $this->jwtService->getClaimFromToken($token);
    }

    /**
     * testRefreshToken method
     */
    public function testRefreshToken()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken(true);

        $this->claimManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $this->claimManager->shouldReceive('remove')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }));

        $newToken = $this->jwtService->refreshToken($token);

        $items = explode('.', $newToken);
        $claimBody = json_decode(base64_decode($items[1]));

        $this->assertEquals('http://www.test.com', $claimBody->iss);
        $this->assertEquals($now, $claimBody->iat);
        $this->assertEquals($now + 60000, $claimBody->exp);
        $this->assertEquals($now + 6000, $claimBody->nat);
    }

    /**
     * testRefreshUnRefreshableToken method
     */
    public function testRefreshUnRefreshableToken()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken();

        $this->claimManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\UnRefreshableException::class);

        $newToken = $this->jwtService->refreshToken($token);
    }

    /**
     * testInvalidateToken method
     */
    public function testInvalidateToken()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken();

        $this->claimManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $this->claimManager->shouldReceive('remove')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }));

        $this->jwtService->invalidateToken($token);
    }

    /**
     * testWipeUserTokens method
     */
    public function testWipeUserTokens()
    {
        $claim = $this->getClaim();

        $this->claimManager->shouldReceive('removeAll')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }));

        $this->jwtService->wipeUserTokens($claim);
    }

    /**
     * getToken method
     *
     * @param bool $refreshable
     * @param int $ttl
     * @return string
     */
    protected function getToken($refreshable = false, $ttl = 100)
    {
        $claim = $this->getClaim($refreshable, $ttl);

        $this->claimManager->shouldReceive('add')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }));

        $token = $this->jwtService->getTokenForClaim($claim);

        return $token;
    }

    /**
     * getClaim method
     *
     * @param bool $refreshable
     * @param int $ttl
     * @return Claim
     */
    protected function getClaim($refreshable = false, $ttl = 100)
    {
        Config::shouldReceive('get')
            ->once()
            ->with('app.url')
            ->andReturn('http://www.test.com');

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.ttl')
            ->andReturn($ttl);

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.ttl')
            ->andReturn($ttl);

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.algo')
            ->andReturn('HS256');

        $claim = new Claim([
            'sub' => 5,
            'aud' => 'User',
            'refresh' => $refreshable
        ]);

        return $claim;
    }

}