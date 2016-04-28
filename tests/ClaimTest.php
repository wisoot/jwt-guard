<?php

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Claim;

class ClaimTest extends PHPUnit_Framework_TestCase
{

    /**
     * testConstructor method
     */
    public function testConstructor()
    {
        $ttl = 100;
        $now = Carbon::now()->timestamp;

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

        $claim = new Claim();

        $this->assertEquals('http://www.test.com', $claim->iss);
        $this->assertEquals($now, $claim->iat, '', 2);
        $this->assertEquals($now + 6000, $claim->exp, '', 2);
        $this->assertEquals($now + 6000, $claim->nat, '', 2);
        $this->assertEquals(0, $claim->leeway);
    }

    /**
     * testCreateClaim method
     */
    public function testCreateClaim()
    {
        $now = Carbon::now()->timestamp;

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        $claim = new Claim([
            'iss' => 'http://www.test.com',
            'iat' => $now,
            'exp' => $now + 6000,
            'nat' => $now + 6000,
            'jti' => 'asdjhasiudhasud'
        ]);

        $this->assertEquals('http://www.test.com', $claim->iss);
        $this->assertEquals($now, $claim->iat);
        $this->assertEquals($now + 6000, $claim->exp);
        $this->assertEquals($now + 6000, $claim->nat);
        $this->assertEquals('asdjhasiudhasud', $claim->jti);
        $this->assertEquals(0, $claim->leeway);
    }

    /**
     * testCreateClaimWithMalformedException method
     */
    public function testCreateClaimWithMalformedException()
    {
        $now = Carbon::now()->timestamp;

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\MalformedException::class);

        $claim = new Claim([
            'iss' => 'http://www.test.com',
            'iat' => $now,
            'exp' => $now - 6000,
            'nat' => $now - 6000,
            'jti' => 'asdjhasiudhasud'
        ]);
    }

    /**
     * testCreateClaimWithInaccessibleException method
     */
    public function testCreateClaimWithInaccessibleException()
    {
        $now = Carbon::now()->timestamp;

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\InaccessibleException::class);

        $claim = new Claim([
            'iss' => 'http://www.test.com',
            'iat' => $now - 6000,
            'exp' => $now + 6000,
            'nat' => $now - 10,
            'jti' => 'asdjhasiudhasud'
        ]);
    }

    /**
     * testCreateClaimWithTokenExpiredException method
     */
    public function testCreateClaimWithTokenExpiredException()
    {
        $now = Carbon::now()->timestamp;

        Config::shouldReceive('get')
            ->once()
            ->with('jwt.leeway')
            ->andReturn(0);

        $this->setExpectedException(\WWON\JwtGuard\Exceptions\TokenExpiredException::class);

        $claim = new Claim([
            'iss' => 'http://www.test.com',
            'iat' => $now - 6000,
            'exp' => $now - 1000,
            'nat' => $now - 1000,
            'jti' => 'asdjhasiudhasud'
        ]);
    }

}