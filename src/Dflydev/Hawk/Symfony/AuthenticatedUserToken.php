<?php

namespace Dflydev\Hawk\Symfony;

class AuthenticatedUserToken extends UserToken
{
    public function __construct($providerKey, $user, $roles = array())
    {
        parent::__construct($providerKey, $roles);
        $this->setUser($user);
        $this->setAuthenticated(true);
    }
}
