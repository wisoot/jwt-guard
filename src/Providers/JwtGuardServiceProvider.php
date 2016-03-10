<?php

namespace WWON\JwtGuard\Providers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use Tymon\JWTAuth\Providers\JWTAuthServiceProvider;
use WWON\JwtGuard\Contract\TokenManager as TokenManagerContract;
use WWON\JwtGuard\JwtGuard;
use WWON\JwtGuard\TokenManager;

class JwtGuardServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Boot the service provider.
     */
    public function boot()
    {
        Auth::extend('jwt', function($app, $name, array $config) {
            return new JwtGuard(
                $app['auth']->createUserProvider($config['provider']),
                $app[TokenManagerContract::class],
                $app['request']
            );
        });

        $this->publishConfig();

        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations')
        ], 'migrations');
    }

    /**
     * Publish the configuration file.
     *
     * @return    void
     */
    private function publishConfig()
    {
        $configFile = __DIR__ . '/../config/jwt_guard.php';

        $this->publishes([
            $configFile => config_path('jwt_guard.php')
        ], 'config');

        $this->mergeConfigFrom($configFile, 'jwt_guard');
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerTymonJwtAuth();

        $this->app->bind(TokenManagerContract::class, TokenManager::class);

        $this->rebindRequests();
    }

    /**
     * Register the Tymon JWT Auth service provider.
     *
     * @return    void
     */
    private function registerTymonJwtAuth()
    {
        $provider = new JWTAuthServiceProvider($this->app);

        $provider->register();
    }

    /**
     * Rebind app requests to set a custom user resolver.
     *
     * @return    void
     */
    protected function rebindRequests()
    {
        $this->app->rebinding('request', function ($app, $request) {
            $request->setUserResolver(function ($guard = null) {
                return auth()->guard($guard)->user();
            });
        });
    }

}