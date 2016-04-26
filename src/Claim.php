<?php

namespace WWON\JwtGuard;

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