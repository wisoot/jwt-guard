<?php

namespace WWON\JwtGuard\Providers;

use Illuminate\Support\ServiceProvider;
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
        \Auth::extend('jwt', function($app, $name, array $config) {
            // Return an instance of Illuminate\Contracts\Auth\Guard...

            return new JwtGuard(
                \Auth::createUserProvider($config['provider']),
                $this->app->make(TokenManagerContract::class),
                $app['request']
            );
        });

        $this->publishes([
            __DIR__ . '/../config/jwt_guard.php' => config_path('jwt_guard.php')
        ], 'config');

        $this->publishes([
            __DIR__ . '/../database/migrations/' => database_path('migrations')
        ], 'migrations');
    }

    /**
     * Register any application services.
     *
     * This service provider is a great spot to register your various container
     * bindings with the application. As you can see, we are registering our
     * "Registrar" implementation here. You can add your own bindings too!
     *
     * @return void
     */
    public function register()
    {
        $this->app->bind(TokenManagerContract::class, TokenManager::class);
    }

}