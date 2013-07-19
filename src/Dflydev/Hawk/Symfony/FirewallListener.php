<?php

namespace Dflydev\Hawk\Symfony;

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
    protected $authenticationEntryPoint;
    protected $options = array(
        'header_field' => 'Authorization',
    );

    public function __construct(SecurityContextInterface $securityContext, 
                                AuthenticationManagerInterface $authenticationManager, 
                                AuthenticationEntryPointInterface $authenticationEntryPoint, 
                                array $options = array())
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
        $this->options = array_merge($this->options, $options);
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $token = new UserToken();
        $token->request = $request;

        if (!$request->headers->has($this->options['header_field'])) {
            $event->setResponse($this->authenticationEntryPoint->start($request));
            return;
        }

        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);
            return;
        } catch (AuthenticationException $failed) {
            $event->setResponse($this->authenticationEntryPoint->start($request, $failed));
        }
    }
}
