<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class FirewallListener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $providerKey;
    protected $authenticationEntryPoint;
    protected $options = [
        'header_field' => 'Authorization', 
    ]; 

    public function __construct(SecurityContextInterface $securityContext, 
                                AuthenticationManagerInterface $authenticationManager, 
                                $providerKey, 
                                AuthenticationEntryPointInterface $authenticationEntryPoint, 
                                array $options = []) 
    { 
        if (empty($providerKey)) { 
            throw new \InvalidArgumentException('$providerKey must not be empty.'); 
        } 

        $this->securityContext = $securityContext; 
        $this->authenticationManager = $authenticationManager; 
        $this->providerKey = $providerKey; 
        $this->authenticationEntryPoint = $authenticationEntryPoint; 
        $this->options = array_merge($this->options, $options);
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        /*
         * Some other listeners check the security context here, in the event 
         * that the context listener has added an authenticated token to the 
         * context (from the session). I'm explicitly not doing that as Hawk 
         * should always be used with the stateless flag anyway.
         */

        /*
         * We could pass in the header_field as part of an options array to the 
         * constructor and return early here (as in set the response with the 
         * authenticationEntryPoint).
         */
        if (!$request->headers->has($this->options['header_field'])) {
            $event->setResponse($this->authenticationEntryPoint->start($request));
            return;
        }

        $token = static::createToken($this->providerKey, $request, $this->options['header_field']);

        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);
        } catch (AuthenticationException $failed) {
            $event->setResponse($this->authenticationEntryPoint->start($request, $failed));
        }
    }

    protected static function createToken($providerKey, Request $request, $headerField = 'Authorization')
    {
        return new UserToken(
            $providerKey,
            array(), // roles
            $request->getMethod(),
            $request->getHost(),
            $request->getPort(),
            $request->getRequestUri(),
            $request->headers->get('Content-type'),
            $request->getContent() !== "" ? $request->getContent() : null,
            $request->headers->get($headerField)
        );
    }
}
