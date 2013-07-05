<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class Listener implements ListenerInterface
{
    protected $securityContext;
    protected $authenticationManager;
    protected $authenticationEntryPoint;

    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, AuthenticationEntryPointInterface $authenticationEntryPoint)
    {
        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->authenticationEntryPoint = $authenticationEntryPoint;
    }

    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $token = new UserToken();
        $token->request = $request;

        // I think we need to check to see if the header is set here, if not, 
        // do whatever is needed to activate the AuthenticationEntryPoint
        //
        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);
            return;
        } catch (AuthenticationException $failed) {
            $event->setResponse($this->authenticationEntryPoint->start($request, $failed));
        }
    }
}
