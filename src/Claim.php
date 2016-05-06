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
     * audience
     *
     * @var string
     */
    public $aud;

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
     * refreshable - whether the token can be refreshed
     *
     * @var bool
     */
    public $refresh = false;

    /**
     * timestamp when this object is instantiate
     *
     * @var int
     */
    protected $now;

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
        $data = $this->getDataMergedWithDefault($data);

        foreach ($data as $key => $value) {
            $attribute = camel_case($key);

            if (property_exists($this, $attribute)) {
                $this->{$attribute} = $value;
            }
        }

        $this->generateJti();

        $this->leeway = Config::get('jwt.leeway');

        $this->validate();
    }

    /**
     * getDataMergedWithDefault method
     *
     * @param array $data
     * @return array
     */
    protected function getDataMergedWithDefault(array $data = [])
    {
        $this->now = Carbon::now()->timestamp;
        $ttl = $this->refresh || !empty($data['refresh'])
            ? Config::get('jwt.refresh_ttl')
            : Config::get('jwt.ttl');

        $data = array_merge([
            'iss' => Config::get('app.url'),
            'iat' => $this->now,
            'exp' => intval($this->now + ($ttl * 60)),
            'nat' => intval($this->now + (Config::get('jwt.ttl') * 60))
        ], $data);

        return $data;
    }

    /**
     * generateJti method
     */
    protected function generateJti()
    {
        if (empty($this->jti)) {
            $this->jti = md5("{$this->aud}.{$this->sub}.{$this->iat}." . rand(1000, 1999));
        }
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
        $compareTime = $this->now + $this->leeway;

        if (empty($this->sub)) {
            throw new MalformedException;
        }

        if (empty($this->aud)) {
            throw new MalformedException;
        }

        if ($this->iat > $this->exp || $this->iat > $this->nat) {
            throw new MalformedException;
        }

        if ($this->exp < $compareTime) {
            throw new TokenExpiredException;
        }
    }

    /**
     * validateAccessible method
     *
     * @throws InaccessibleException
     */
    public function validateAccessible()
    {
        $compareTime = $this->now + $this->leeway;

        if ($this->nat < $compareTime) {
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
        $fields = [
            'sub', 'iss', 'aud', 'iat',
            'exp', 'nbf', 'nat', 'jti'
        ];

        foreach ($fields as $field) {
            if (!empty($this->{$field})) {
                $data[$field] = $this->{$field};
            }
        }

        if ($this->refresh) {
            $data['refresh'] = true;
        }

        return $data;
    }

}