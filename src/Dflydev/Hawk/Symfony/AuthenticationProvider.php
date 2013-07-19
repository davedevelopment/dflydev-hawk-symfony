<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Dflydev\Hawk\Server\Server;
use Dflydev\Hawk\Server\UnauthorizedException;

class AuthenticationProvider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $hawkServer;
    private $options = array(
        'header_field' => 'Authorization',
    );

    public function __construct(UserProviderInterface $userProvider, Server $hawkServer, array $options = array())
    {
        $this->userProvider = $userProvider;
        $this->hawkServer = $hawkServer;
        $this->options = array_merge($this->options, $options);
    }

    public function authenticate(TokenInterface $token)
    {
        try {

            $response = $this->hawkServer->authenticate(
                $token->request->getMethod(),
                $token->request->getHost(),
                $token->request->getPort(),
                $token->request->getRequestUri(),
                $token->request->headers->get('Content-type'),
                $token->request->getContent() !== "" ? $token->request->getContent() : null,
                $token->request->headers->get($this->options['header_field'])
            );

            $authenticatedToken = new UserToken($response->credentials()->getRoles());
            $authenticatedToken->setUser($response->credentials());

            return $authenticatedToken;

        } catch (UnauthorizedException $e) {
            throw new AuthenticationException('The Hawk authentication failed.');
        }
    }


    public function supports(TokenInterface $token)
    {
        return ($token instanceof UserToken && $token->request->headers->has($this->options['header_field']));
    }
}
