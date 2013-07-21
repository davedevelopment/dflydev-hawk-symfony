<?php

namespace Dflydev\Hawk\Symfony;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;
use Symfony\Component\HttpFoundation\Request;

class UserToken extends AbstractToken
{
    public $request;
    protected $providerKey;

    public function __construct($providerKey, array $roles = [], $method = null, $host = null, $port = null, $resource = null, $contentType = null, $payload = null, $header = null)
    {
        parent::__construct($roles);

        $this->providerKey = $providerKey;
        $this->method = $method;
        $this->host = $host;
        $this->port = $port;
        $this->resource = $resource;
        $this->contentType = $contentType;
        $this->payload = $payload;
        $this->header = $header;
    }

    public function getCredentials()
    {
        return '';
    }        

    public function getProviderKey()
    {
        return $this->providerKey;
    }

    public function getMethod()
    {
        return $this->method;
    }

    public function getHost()
    {
        return $this->host;
    }

    public function getPort()
    {
        return $this->port;
    }

    public function getResource()
    {
        return $this->resource;
    }

    public function getContentType()
    {
        return $this->contentType;
    }

    public function getPayload()
    {
        return $this->payload;
    }

    public function getHeader()
    {
        return $this->header;
    }
}
