<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Dflydev\Hawk\Server\Server;
use Dflydev\Hawk\Server\UnauthorizedException;

class Provider implements AuthenticationProviderInterface
{
    private $userProvider;
    private $hawkServer;

    public function __construct(UserProviderInterface $userProvider, Server $hawkServer)
    {
        $this->userProvider = $userProvider;
        $this->hawkServer = $hawkServer;
    }

    public function authenticate(TokenInterface $token)
    {
        $credentialsFunc = function ($username) {
            return $this->userProvider->loadUserByUsername($username);
        };

        $authenticator = $this->hawkServer->createAuthenticatorBuilder($credentialsFunc)->build();

        try {

            $request = $this->hawkServer->createRequest(
                $token->request->getMethod(),
                $token->request->getHost(),
                $token->request->getPort(),
                $token->request->getRequestUri(),
                $token->request->headers->get('Content-type'),
                $token->request->getContent() !== "" ? $token->request->getContent() : null,
                $token->request->headers->get('Authorization')
            );

            list($credentials, $artifacts) = $authenticator->authenticate($request);

            $authenticatedToken = new UserToken($credentials->getRoles());
            $authenticatedToken->setUser($credentials);

            return $authenticatedToken;

        } catch (UnauthorizedException $e) {
            throw new AuthenticationException('The Hawk authentication failed.');
        }
    }


    public function supports(TokenInterface $token)
    {
        return $token instanceof UserToken;
    }
}
