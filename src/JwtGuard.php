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
use Illuminate\Session\TokenMismatchException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class JwtGuard implements Guard
{

    use GuardHelpers;

    /**
     * @var string
     */
    protected $token;

    /**
     * @var TokenManager
     */
    protected $tokenManager;

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
     * @param TokenManager $tokenManager
     * @param Request|null $request
     */
    public function __construct(
        UserProvider $provider,
        TokenManager $tokenManager,
        Request $request = null
    ) {
        $this->provider = $provider;
        $this->tokenManager = $tokenManager;
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
        if (! is_null($this->user)) {
            return $this->user;
        }

        $token = $this->parseAuthenticateString($this->request->header('Authorization'));

        if (empty($token)) {
            return $this->user = null;
        }

        try {
            $payload = \JWTAuth::setToken($token)->getPayload();
            $user = $this->provider->retrieveById($payload['sub']);

            if (!empty($this->user)
                && $this->tokenManager->check($user->getAuthIdentifier(), $payload['jti'])) {

                $this->user = $user;
            }

        } catch (TokenInvalidException $e) {

            $this->user = null;

        } catch (TokenExpiredException $e) {

            $this->user = null;
        }

        return $this->user;

    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return $this->attempt($credentials, false);
    }

    /**
     * Parse token from the authorization header.
     *
     * @param string $authenticateString
     * @return string|null
     */
    protected function parseAuthenticateString($authenticateString)
    {
        $method = 'bearer';

        if (!starts_with(strtolower($authenticateString), $method . ' ')) {
            return null;
        }

        return trim(str_ireplace($method, '', $authenticateString));
    }

    /**
     * Attempt to authenticate a user using the given credentials.
     *
     * @param  array  $credentials
     * @param  bool   $login
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
     * @param  mixed  $user
     * @param  array  $credentials
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return ! is_null($user) && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Fire the attempt event with the arguments.
     *
     * @param  array  $credentials
     * @param  bool  $login
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
     * @param  mixed  $callback
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
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function login(AuthenticatableContract $user)
    {
        $userId = $user->getAuthIdentifier();
        $token = $this->generateTokenForUserId($userId);

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
     * @param int $userId
     * @return string
     */
    protected function generateTokenForUserId($userId)
    {
        $payload = \JWTFactory::make(['sub' => $userId]);
        $token = \JWTAuth::encode($payload);
        $this->tokenManager->add($userId, $payload['jti']);

        return $token->get();
    }

    /**
     * Fire the login event if the dispatcher is set.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  bool  $remember
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
     * @param  mixed  $id
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
        $token = $this->parseAuthenticateString(\Request::header('Authorization'));

        if (empty($token)) {
            return;
        }

        try {
            $payload = \JWTAuth::setToken($token)->getPayload();
            $user = $this->provider->retrieveById($payload['sub']);

            if (!empty($user)) {
                $this->tokenManager->remove($user->getAuthIdentifier(), $payload['jti']);
            }

        } catch (TokenMismatchException $e) { }

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

}