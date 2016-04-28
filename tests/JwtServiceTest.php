<?php

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Contract\TokenManager;
use WWON\JwtGuard\JwtService;

class JwtServiceTest extends PHPUnit_Framework_TestCase
{

    /**
     * @var Mockery\MockInterface
     */
    private $tokenManager;
    
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

        $this->tokenManager = Mockery::mock(TokenManager::class);
        $this->jwtService = new JwtService($this->tokenManager);
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
     * testGetTokenForUser method
     */
    public function testGetTokenForUser()
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
     * testGetUserIdFromToken method
     */
    public function testGetUserIdFromToken()
    {
        $token = $this->getToken();

        $this->tokenManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $userId = $this->jwtService->getUserIdFromToken($token);

        $this->assertEquals(5, $userId);
    }

    /**
     * testGetUserIdFromTokenWithInvalidClaim method
     */
    public function testGetUserIdFromTokenWithInvalidClaim()
    {
        $token = $this->getToken();

        $this->tokenManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(false);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\InvalidTokenException::class);

        $userId = $this->jwtService->getUserIdFromToken($token);
    }

    /**
     * testRefreshToken method
     */
    public function testRefreshToken()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken(true);

        $this->tokenManager->shouldReceive('check')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                    && $claim->iss == 'http://www.test.com';
            }))
            ->andReturn(true);

        $this->tokenManager->shouldReceive('remove')
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
        $this->assertEquals($now + 6000, $claimBody->exp);
        $this->assertEquals($now + 6000, $claimBody->nat);
    }

    /**
     * testRefreshUnRefreshableToken method
     */
    public function testRefreshUnRefreshableToken()
    {
        $now = Carbon::now()->timestamp;

        $token = $this->getToken();

        $this->tokenManager->shouldReceive('check')
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
     * getToken method
     *
     * @param bool $refreshable
     * @param int $ttl
     * @return string
     */
    protected function getToken($refreshable = false, $ttl = 100)
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

        $this->tokenManager->shouldReceive('add')
            ->once()
            ->with(Mockery::on(function($claim) {
                return $claim->sub == 5
                && $claim->iss == 'http://www.test.com';
            }));

        $token = $this->jwtService->getTokenForUser(new User(), $refreshable);

        return $token;
    }

}