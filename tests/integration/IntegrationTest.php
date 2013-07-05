<?php

namespace tests\integration;

use Dflydev\Hawk\Credentials\CredentialsInterface;
use Dflydev\Hawk\Symfony\AuthenticationEntryPoint as HawkAuthenticationEntryPoint;
use Dflydev\Hawk\Symfony\Listener as HawkListener;
use Dflydev\Hawk\Symfony\Provider as HawkProvider;
use Dflydev\Hawk\Crypto\Crypto;
use Dflydev\Hawk\Server\Server;
use Silex\Application;
use Silex\Provider\SecurityServiceProvider;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;

class IntegrationTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $this->app = $this->getApp();
        $this->client = new Client($this->app);
    }

    /** @test */
    public function shouldAuthoriseValidRequest()
    {
        $this->client->request("GET", "/resource/4?filter=a", [], [], [
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha256", "12345",  time(), uniqid(), 'GET', "/resource/4?filter=a", "localhost", 80, null, "hello", null, null),
        ]);

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
    }  

    /** @test */
    public function should401WithIncorrectCreds()
    {
        $this->client->request("GET", "/resource/4?filter=a", [], [], [
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha256", "67890",  time(), uniqid(), 'GET', "/resource/4?filter=a", "localhost", 80, null, "hello", null, null),
        ]);

        $this->assertEquals(401, $this->client->getResponse()->getStatusCode());
    }

    /** @test */
    public function should401WithIncorrectAlgo()
    {
        $this->client->request("GET", "/resource/4?filter=a", [], [], [
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha1", "12345",  time(), uniqid(), 'GET', "/resource/4?filter=a", "localhost", 80, null, "hello", null, null),
        ]);

        $this->assertEquals(401, $this->client->getResponse()->getStatusCode());
    }

    /** @test */
    public function should401WithoutHeader()
    {
        $this->client->request("GET", "/resource/4?filter=a");
        $this->assertEquals(401, $this->client->getResponse()->getStatusCode());
    }  

    /** @test */
    public function shouldPreventReplayAttacks()
    {
        $this->client->request("GET", "/resource/4?filter=a", [], [], [
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha256", "12345",  strtotime("-5 days"), uniqid(), 'GET', "/resource/4?filter=a", "localhost", 80, null, "hello", null, null),
        ]);
        $this->assertEquals(401, $this->client->getResponse()->getStatusCode());
    }  

    /** @test */
    public function shouldAuthoriseValidRequestWithPayloadVerification()
    {
        $this->client->request("POST", "/resource/4", [], [], [
            'HTTP_CONTENT_TYPE' => 'text/plain',
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha256", "12345",  time(), uniqid(), 'POST', "/resource/4", "localhost", 80, null, "hello", null, null, "name=dave", "application/x-www-form-urlencoded"),
        ], "name=dave");

        $this->assertEquals(200, $this->client->getResponse()->getStatusCode());
    }  

    /** @test */
    public function should401WithInvalidPayloadVerification()
    {
        $this->client->request("POST", "/resource/4", [], [], [
            'HTTP_CONTENT_TYPE' => 'text/plain',
            'HTTP_AUTHORIZATION' => $this->generateHeader("dave", "sha256", "12345",  time(), uniqid(), 'POST', "/resource/4", "localhost", 80, null, "hello", null, null, "name=dave", "application/x-www-form-urlencoded"),
        ], "asdjnsadgf jklndfg ");

        $this->assertEquals(401, $this->client->getResponse()->getStatusCode());
    }  

    protected function getApp()
    {
        $app = new Application;        
        $app['debug'] = true;
        unset($app['exception_handler']);

        $app->register(new SecurityServiceProvider(), array(
            "security.firewalls" => array(
                "api" => array(
                    "pattern" => "^/.*",
                    "hawk" => true,
                ),
            ),
        ));

        $app['dflydev.hawk.crypto'] = $app->share(function ($app) {
            return new Crypto;
        });

        $app['dflydev.hawk.server'] = $app->share(function ($app) {
            return new Server($app['dflydev.hawk.crypto']);
        });

        $app['security.authentication_listener.factory.hawk'] = $app->protect(function($name, $options) use ($app) {
            return array(
                'security.authentication_provider.'.$name.'.hawk',
                'security.authentication_listener.'.$name.'.hawk',
                'security.entry_point.hawk',
                'pre_auth',
            );
        });

        $app['security.entry_point.hawk'] = $app->share(function() use ($app) {
            return new HawkAuthenticationEntryPoint();
        });

        $app['security.user_provider.api'] = $app->share(function() use ($app) {
            return new UserProvider(array(
                new User("dave", "sha256", "12345", array("ROLE_USER")),
                new User("beau", "sha256", "67890", array("ROLE_USER")),
            ));
        });

        $app['security.authentication_provider.api.hawk'] = $app->share(function ($app) {
            return new HawkProvider($app['security.user_provider.api'], $app['dflydev.hawk.server']);
        });

        $app['security.authentication_listener.api.hawk'] = $app->share(function() use ($app) {
            return new HawkListener(
                $app['security'],
                $app['security.authentication_manager'],
                $app['security.entry_point.hawk']
            );
        });

        $app->match("/resource/{id}", function ($id) {
            return $id;
        });

        return $app;
    }

    protected function generateHeader($id, $algo, $key, $ts, $nonce, $method, $requestUri, $host, $port, $hash, $ext, $app, $dlg, $payload = null, $contentType = null) {
        if ($payload) {
            $hash = $this->generatePayloadHash($algo, $payload, $contentType);
        }

        $mac = $this->generateMac($algo, $key, $ts, $nonce, $method, $requestUri, $host, $port, $hash, $ext, $app, $dlg);
        $header = "Hawk id=\"$id\", ts=\"$ts\", nonce=\"$nonce\", mac=\"$mac\", ext=\"$ext\"";

        if ($hash) {
            $header .= ", hash=\"$hash\"";
        }

        return $header;
    }

    protected function generateMac($algo, $key, $ts, $nonce, $method, $requestUri, $host, $port, $hash, $ext, $app, $dlg) {
        $data = "hawk.1.header\n".$ts."\n".$nonce."\n".$method."\n".$requestUri."\n".$host."\n".$port."\n".$hash."\n".$ext."\n";
        if ($app) {
            $data .= $app."\n".$dlg."\n";
        }
        return base64_encode(hash_hmac($algo, $data, $key, false)); // change this when PR1 gets merged
    }

    protected function generatePayloadHash($algo, $payload, $contentType)
    {
        $data = "hawk.1.payload\n".$contentType."\n".$payload."\n";
        return base64_encode(hash($algo, $data, false)); // change this when PR1 gets merged
    }
}

class User implements CredentialsInterface, UserInterface
{
    public $key;
    public $algorithm;
    public $username;
    public $roles;

    public function __construct($username, $algorithm, $key, array $roles = array())
    {
        $this->username = $username;
        $this->algorithm = $algorithm;
        $this->key = $key;
        $this->roles = $roles;
    }

    public function key()
    {
        return $this->key;
    }

    public function algorithm()
    {
        return $this->algorithm;
    }

    public function id()
    {
        return $this->username;
    }

    public function getRoles()
    {
        return $this->roles;
    }

    public function getPassword() {}

    public function getSalt() {}

    public function getUsername()
    {
        return $this->username;
    }

    public function eraseCredentials() 
    {
        unset ($this->key);
    }
}

class UserProvider implements UserProviderInterface
{
    protected $users;

    public function __construct(array $users)
    {
        $this->users = $users;
    }

    public function loadUserByUsername($username)
    {
        foreach ($this->users as $user) {
            if ($user->getUsername() == $username) {
                return $user;
            }
        }

        throw new UsernameNotFoundException();
    }

    public function refreshUser(UserInterface $user)
    {
        return $this->loadUserByUsername($user->getUsername());
    }

    public function supportsClass($class)
    {
        return $class === 'tests\integration\User';
    }
}
