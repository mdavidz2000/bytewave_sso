<?php
namespace App\Helpers;

use Psr\Http\Message\ResponseInterface;

class ResponseHelper
{
    public static function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withStatus($status);
    }
}