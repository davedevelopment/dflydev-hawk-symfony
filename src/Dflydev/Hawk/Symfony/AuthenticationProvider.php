<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Dflydev\Hawk\Server\Server;
use Dflydev\Hawk\Server\UnauthorizedException;

class AuthenticationProvider implements AuthenticationProviderInterface
{
    protected $hawkServer;
    protected $providerKey;
    protected $options = array(
        'header_field' => 'Authorization',
    );

    public function __construct(Server $hawkServer, $providerKey, array $options = array())
    {
        $this->hawkServer = $hawkServer;
        $this->providerKey = $providerKey;
        $this->options = array_merge($this->options, $options);
    }

    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            return null;
        }

        try {

            $response = $this->hawkServer->authenticate(
                $token->getMethod(),
                $token->getHost(),
                $token->getPort(),
                $token->getResource(),
                $token->getContentType(),
                $token->getPayload(),
                $token->getHeader()
            );

            $authenticatedToken = new UserToken($this->providerKey, $response->credentials()->getRoles());
            $authenticatedToken->setUser($response->credentials());

            return $authenticatedToken;

        } catch (UnauthorizedException $e) {
            throw new AuthenticationException('The Hawk authentication failed.');
        }
    }


    public function supports(TokenInterface $token)
    {
        return ($token instanceof UserToken && $this->providerKey == $token->getProviderKey());
    }
}
