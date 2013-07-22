<?php

namespace Dflydev\Hawk\Symfony;

use Dflydev\Hawk\Credentials\CredentialsInterface;

interface UserInterface extends CredentialsInterface
{
    function getRoles();
    function __toString();
}
