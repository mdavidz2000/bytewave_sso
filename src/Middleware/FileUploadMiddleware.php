<?php
namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

class FileUploadMiddleware
{
    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $uploadedFiles = $request->getUploadedFiles();
        
        // Validate each uploaded file
        foreach ($uploadedFiles as $file) {
            if ($file->getError() !== UPLOAD_ERR_OK) {
                $response = new \Slim\Psr7\Response();
                $response->getBody()->write(json_encode([
                    'error' => 'upload_error',
                    'message' => 'File upload failed'
                ]));
                return $response->withStatus(400)
                    ->withHeader('Content-Type', 'application/json');
            }
            
            // Check file size
            if ($file->getSize() > 5 * 1024 * 1024) { // 5MB
                $response = new \Slim\Psr7\Response();
                $response->getBody()->write(json_encode([
                    'error' => 'file_too_large',
                    'message' => 'File size must be less than 5MB'
                ]));
                return $response->withStatus(400)
                    ->withHeader('Content-Type', 'application/json');
            }
            
            // Check file type
            $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
            $mimeType = $file->getClientMediaType();
            
            if (!in_array($mimeType, $allowedTypes)) {
                $response = new \Slim\Psr7\Response();
                $response->getBody()->write(json_encode([
                    'error' => 'invalid_file_type',
                    'message' => 'Only JPEG, PNG, and GIF images are allowed'
                ]));
                return $response->withStatus(400)
                    ->withHeader('Content-Type', 'application/json');
            }
        }
        
        return $handler->handle($request);
    }
}