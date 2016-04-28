<?php

namespace WWON\JwtGuard;

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Exceptions\InaccessibleException;
use WWON\JwtGuard\Exceptions\MalformedException;
use WWON\JwtGuard\Exceptions\TokenExpiredException;

class Claim
{

    /**
     * subject
     *
     * @var mixed
     */
    public $sub;

    /**
     * issuer
     *
     * @var string
     */
    public $iss;

    /**
     * issued at
     *
     * @var int
     */
    public $iat;

    /**
     * expiration time
     *
     * @var int
     */
    public $exp;

    /**
     * not before
     *
     * @var int
     */
    public $nbf;

    /**
     * not after
     *
     * @var int
     */
    public $nat;

    /**
     * JWT identity
     *
     * @var string
     */
    public $jti;

    /**
     * leeway for using in comparing time
     *
     * @var int
     */
    public $leeway;

    /**
     * Claim constructor
     *
     * @param array $data
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    public function __construct(array $data = [])
    {
        foreach ($data as $key => $value) {
            $attribute = camel_case($key);

            if (property_exists($this, $attribute)) {
                $this->{$attribute} = $value;
            }
        }

        if (empty($this->iss)) {
            $this->iss = Config::get('app.url');
        }

        if (empty($this->iat)) {
            $this->iat = Carbon::now()->timestamp;
        }

        if (empty($this->exp)) {
            $this->exp = $this->iat + (Config::get('jwt.ttl') * 60); // turns minute into second
        }

        if (empty($this->nat)) {
            $this->nat = $this->iat + (Config::get('jwt.ttl') * 60); // turns minute into second
        }

        if (empty($this->jti)) {
            $this->jti = md5("{$this->sub}.{$this->iat}." . rand(1000, 1999));
        }

        if (empty($this->leeway)) {
            $this->leeway = Config::get('jwt.leeway');
        }

        $this->validate();
    }

    /**
     * validate method
     *
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     */
    protected function validate()
    {
        $now = Carbon::now()->timestamp + $this->leeway;

        if ($this->iat > $this->exp || $this->iat > $this->nat) {
            throw new MalformedException;
        }

        if ($this->exp < $now) {
            throw new TokenExpiredException;
        }

        if ($this->nat < $now) {
            throw new InaccessibleException;
        }
    }

    /**
     * toArray method
     *
     * @return array
     */
    public function toArray()
    {
        $data = [];

        if (!empty($this->sub)) {
            $data['sub'] = $this->sub;
        }

        if (!empty($this->iss)) {
            $data['iss'] = $this->iss;
        }

        if (!empty($this->iat)) {
            $data['iat'] = $this->iat;
        }

        if (!empty($this->exp)) {
            $data['exp'] = $this->exp;
        }

        if (!empty($this->nbf)) {
            $data['nbf'] = $this->nbf;
        }

        if (!empty($this->nat)) {
            $data['nat'] = $this->nat;
        }

        if (!empty($this->jti)) {
            $data['jti'] = $this->jti;
        }

        return $data;
    }

}