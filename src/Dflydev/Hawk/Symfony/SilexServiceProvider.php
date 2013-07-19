<?php

namespace Dflydev\Hawk\Symfony;

use Silex\ServiceProviderInterface;
use Silex\Application;
use Dflydev\Hawk\Symfony\AuthenticationEntryPoint as HawkAuthenticationEntryPoint;
use Dflydev\Hawk\Symfony\FirewallListener as HawkListener;
use Dflydev\Hawk\Symfony\AuthenticationProvider as HawkProvider;
use Dflydev\Hawk\Crypto\Crypto;
use Dflydev\Hawk\Server\Server;
use Dflydev\Hawk\Server\ServerBuilder;

class SilexServiceProvider implements ServiceProviderInterface
{
    
    public function register(Application $app)
    {
        $app['security.authentication_listener.factory.hawk'] = $app->protect(function($name, $options) use ($app) {

            if (!isset($app['security.'.$name.'.hawk.crypto'])) {
                $app['security.'.$name.'.hawk.crypto'] = $app['security.hawk.crypto._proto']($name, $options);
            }

            if (!isset($app['security.'.$name.'.hawk.server'])) {
                $app['security.'.$name.'.hawk.server'] = $app['security.hawk.server._proto']($name, $options);
            }

            if (!isset($app['security.entry_point.'.$name.'.hawk'])) {
                $app['security.entry_point.'.$name.'.hawk'] = $app['security.entry_point.hawk._proto']($name, $options);
            }

            if (!isset($app['security.authentication_listener.'.$name.'.hawk'])) {
                $app['security.authentication_listener.'.$name.'.hawk'] = $app['security.authentication_listener.hawk._proto']($name, $options);
            }

            if (!isset($app['security.authentication_provider.'.$name.'.hawk'])) {
                $app['security.authentication_provider.'.$name.'.hawk'] = $app['security.authentication_provider.hawk._proto']($name);
            }

            return array(
                'security.authentication_provider.'.$name.'.hawk',
                'security.authentication_listener.'.$name.'.hawk',
                'security.entry_point.'.$name.'.hawk',
                'pre_auth',
            );
        });

        $app['security.hawk.server._proto'] = $app->protect(function ($name, $options) use ($app) {
            return $app->share(function ($app) use ($name, $options) {

                $credentialsFunc = function ($username) use ($name, $app) {
                    return $app['security.user_provider.'.$name]->loadUserByUsername($username);
                };

                $server = ServerBuilder::create($credentialsFunc)
                    ->setCrypto($app['security.'.$name.'.hawk.crypto'])
                    ->build();

                return $server;
            });
        });

        $app['security.hawk.crypto._proto'] = $app->protect(function ($name, $options) use ($app) {
            return $app->share(function ($app) use ($name, $options) {
                return new Crypto;
            });
        });

        $app['security.entry_point.hawk._proto'] = $app->protect(function($name, $options) use ($app) {
            return new HawkAuthenticationEntryPoint();
        });

        $app['security.authentication_provider.hawk._proto'] = $app->protect(function ($name) use ($app) {
            return new HawkProvider($app['security.user_provider.'.$name], $app['security.'.$name.'.hawk.server']);
        });

        $app['security.authentication_listener.hawk._proto'] = $app->protect(function($name, $options) use ($app) {
            return $app->share(function () use ($app, $name, $options) {
                return new HawkListener(
                    $app['security'],
                    $app['security.authentication_manager'],
                    $app['security.entry_point.'.$name.'.hawk']
                );
            });
        });
    }

    public function boot(Application $app)
    {
        // noop
    }
}
