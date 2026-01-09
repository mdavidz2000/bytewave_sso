<?php
namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

class RateLimitMiddleware
{
    private $pdo;
    private $limit;
    private $window;

    public function __construct(\PDO $pdo, int $limit = 100, int $window = 3600)
    {
        $this->pdo = $pdo;
        $this->limit = $limit;
        $this->window = $window;
    }

    public function __invoke(Request $request, RequestHandler $handler): Response
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $path = $request->getUri()->getPath();
        
        $currentTime = time();
        $windowStart = $currentTime - $this->window;
        
        // Count requests in current window
        $stmt = $this->pdo->prepare("
            SELECT COUNT(*) as count 
            FROM rate_limits 
            WHERE ip_address = :ip 
            AND path = :path 
            AND timestamp > :window_start
        ");
        
        $stmt->execute([
            'ip' => $ip,
            'path' => $path,
            'window_start' => $windowStart
        ]);
        
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);
        $requestCount = $result['count'] ?? 0;
        
        if ($requestCount >= $this->limit) {
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode([
                'error' => 'rate_limit_exceeded',
                'message' => 'Too many requests. Please try again later.'
            ]));
            
            return $response->withStatus(429)
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Retry-After', $this->window);
        }
        
        // Log this request
        $stmt = $this->pdo->prepare("
            INSERT INTO rate_limits (ip_address, path, timestamp) 
            VALUES (:ip, :path, :timestamp)
        ");
        
        $stmt->execute([
            'ip' => $ip,
            'path' => $path,
            'timestamp' => $currentTime
        ]);
        
        // Clean old records
        $this->cleanOldRecords();
        
        return $handler->handle($request);
    }
    
    private function cleanOldRecords(): void
    {
        $oldestTime = time() - ($this->window * 2); // Keep data for 2 windows
        $stmt = $this->pdo->prepare("
            DELETE FROM rate_limits 
            WHERE timestamp < :oldest_time
        ");
        
        $stmt->execute(['oldest_time' => $oldestTime]);
    }
}