<?php

namespace WWON\JwtGuard;

use Carbon\Carbon;
use Illuminate\Support\Facades\Config;

class Claim
{

    /**
     * @var mixed
     */
    public $sub;

    /**
     * @var string
     */
    public $iss;

    /**
     * @var int
     */
    public $iat;

    /**
     * @var int
     */
    public $exp;

    /**
     * @var string
     */
    public $jti;

    /**
     * Claim constructor
     *
     * @param array $data
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

        if (empty($this->iat)) {
            $this->exp = $this->iat + (Config::get('jwt.ttl') * 60); // turns minute into second
        }

        if (empty($this->jti)) {
            $this->jti = md5("{$this->sub}.{$this->iat}." . rand(1000, 1999));
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

        if (!empty($this->jti)) {
            $data['jti'] = $this->jti;
        }

        return $data;
    }

}