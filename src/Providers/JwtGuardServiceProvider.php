<?php

namespace WWON\JwtGuard\Providers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use WWON\JwtGuard\Contract\TokenManager as TokenManagerContract;
use WWON\JwtGuard\JwtGuard;
use WWON\JwtGuard\JwtService;
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
                $app[JwtService::class],
                $app['request']
            );
        });

        $this->publishConfig();
        $this->publishMigration();
    }

    /**
     * Publish the configuration file.
     */
    private function publishConfig()
    {
        $configFile = __DIR__ . '/../config/jwt.php';

        $this->publishes([
            $configFile => config_path('jwt.php')
        ], 'config');

        $this->mergeConfigFrom($configFile, 'jwt');
    }

    /**
     * Publish the migration file.
     */
    private function publishMigration()
    {
        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations')
        ], 'migrations');
    }

    /**
     * Register any application services.
     */
    public function register()
    {
        $this->app->bind(TokenManagerContract::class, TokenManager::class);

        $this->app->rebinding('request', function ($app, $request) {
            $request->setUserResolver(function ($guard = null) {
                return auth()->guard($guard)->user();
            });
        });
    }

}