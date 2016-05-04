<?php

namespace WWON\JwtGuard;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use WWON\JwtGuard\Exceptions\Exception;
use WWON\JwtGuard\Exceptions\InaccessibleException;
use WWON\JwtGuard\Exceptions\InvalidTokenException;
use WWON\JwtGuard\Exceptions\MalformedException;
use WWON\JwtGuard\Exceptions\TokenExpiredException;

class JwtGuard implements Guard
{

    use GuardHelpers;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var bool
     */
    protected $isTokenRefreshable = false;

    /**
     * @var JwtService
     */
    protected $jwtService;

    /**
     * @var Request
     */
    protected $request;

    /**
     * Indicates if the logout method has been called.
     *
     * @var bool
     */
    protected $loggedOut = false;

    /**
     * JwtGuard constructor
     *
     * @param UserProvider $provider
     * @param JwtService $jwtService
     * @param Request|null $request
     */
    public function __construct(
        UserProvider $provider,
        JwtService $jwtService,
        Request $request = null
    ) {
        $this->provider = $provider;
        $this->jwtService = $jwtService;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        // If we've already retrieved the user for the current request we can just
        // return it back immediately. We do not want to fetch the user data on
        // every call to this method because that would be tremendously slow.
        if ($this->user) {
            return $this->user;
        }

        if (!$token = $this->getBearerToken()) {
            return $this->user = null;
        }

        try {
            $this->user = $this->getUserByToken($token);
        } catch (InaccessibleException $e) {
            $this->isTokenRefreshable = true;
            $this->user = null;
        } catch (Exception $e) {
            $this->user = null;
        }

        return $this->user;
    }

    /**
     * Retrieve the user by the given payload.
     *
     * @param string $token
     * @return AuthenticatableContract|null
     * @throws InaccessibleException
     * @throws MalformedException
     * @throws TokenExpiredException
     * @throws InvalidTokenException
     */
    protected function getUserByToken($token)
    {
        $claim = $this->jwtService->getClaimFromToken($token);
        $user = $this->provider->retrieveById($claim->sub);

        if (!empty($user) && get_class($user) !== $claim->aud) {
            throw new InvalidTokenException;
        }

        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param array $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param array $credentials
     * @param bool $login
     * @return bool
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->fireAttemptEvent($credentials, $login);

        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        // If an implementation of UserInterface was returned, we'll ask the provider
        // to validate the user against the given credentials, and if they are in
        // fact valid we'll log the users into the application and return true.
        if ($this->hasValidCredentials($user, $credentials)) {
            if ($login) {
                $this->login($user);
            }

            return true;
        }

        return false;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param mixed $user
     * @param array $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param array $credentials
     * @param bool $login
     * @return void
     */
    protected function fireAttemptEvent(array $credentials, $login)
    {
        if (isset($this->events)) {
            $this->events->fire(new Attempting(
                $credentials, false, $login
            ));
        }
    }

    /**
     * Register an authentication attempt event listener.
     *
     * @param mixed $callback
     * @return void
     */
    public function attempting($callback)
    {
        if (isset($this->events)) {
            $this->events->listen(Attempting::class, $callback);
        }
    }

    /**
     * Log a user into the application.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @return void
     */
    public function login(AuthenticatableContract $user)
    {
        $claim = new Claim([
            'sub' => $user->getAuthIdentifier(),
            'aud' => get_class($user),
            'refresh' => Config::get('jwt.refreshable')
        ]);

        $token = $this->jwtService->getTokenForClaim($claim);

        // If we have an event dispatcher instance set we will fire an event so that
        // any listeners will hook into the authentication events and run actions
        // based on the login and logout events fired from the guard instances.
        $this->fireLoginEvent($user);

        $this->setToken($token);
        $this->setUser($user);
    }

    /**
     * generateTokenForUser method
     *
     * @param string $token
     * @return string
     */
    protected function refreshTokenForUser($token)
    {
        try {
            $newToken = $this->jwtService->refreshToken($token);
        } catch (Exception $e) {
            $newToken = null;
        }

        return $newToken;
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param \Illuminate\Contracts\Auth\Authenticatable $user
     * @param bool  $remember
     * @return void
     */
    protected function fireLoginEvent($user, $remember = false)
    {
        if (isset($this->events)) {
            $this->events->fire(new Login($user, $remember));
        }
    }

    /**
     * Log the given user ID into the application.
     *
     * @param mixed $id
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function loginUsingId($id)
    {
        $this->login($user = $this->provider->retrieveById($id));

        return $user;
    }

    /**
     * Log the user out of the application.
     *
     * @return void
     */
    public function logout()
    {
        if (!$token = $this->getBearerToken()) {
            return;
        }

        try {
            $this->jwtService->invalidateToken($token);
        } catch (Exception $e) { }

        if (isset($this->events)) {
            $this->events->fire(new Logout($this->user));
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;
        $this->token = null;
        $this->loggedOut = true;
    }

    /**
     * log this user out from every token
     *
     * @return void
     */
    public function logoutAll()
    {
        if (!$token = $this->getBearerToken()) {
            return;
        }

        try {
            $user = $this->jwtService->getClaimFromToken($token);

            $this->jwtService->wipeUserTokens($user);

        } catch (Exception $e) { }

        if (isset($this->events)) {
            $this->events->fire(new Logout($this->user));
        }

        // Once we have fired the logout event we will clear the users out of memory
        // so they are no longer available as the user is no longer considered as
        // being signed into this application and should not be available here.
        $this->user = null;
        $this->token = null;
        $this->loggedOut = true;
    }

    /**
     * Refresh user token
     *
     * @return string|null
     */
    public function refreshToken()
    {
        if (!$token = $this->getBearerToken()) {
            return null;
        }

        $this->token = $this->refreshTokenForUser($token);

        return $this->token;
    }

    /**
     * setToken method
     *
     * @param string $token
     */
    public function setToken($token)
    {
        $this->token = $token;
    }

    /**
     * getToken method
     *
     * @return null|string
     */
    public function getToken()
    {
        return $this->token;
    }

    /**
     * isTokenRefreshable method
     */
    public function isTokenRefreshable()
    {
        return $this->isTokenRefreshable;
    }

    /**
     * getBearerToken method
     *
     * @return string|null
     */
    protected function getBearerToken()
    {
        $header = $this->request->header('Authorization', '');

        if (starts_with(strtolower($header), 'bearer ')) {
            return mb_substr($header, 7, null, 'UTF-8');
        }

        return null;
    }

}