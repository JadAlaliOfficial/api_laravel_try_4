<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Cache\RateLimiter;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

class PasswordAttemptThrottle
{
    /**
     * The rate limiter instance.
     *
     * @var \Illuminate\Cache\RateLimiter
     */
    protected $limiter;

    /**
     * Create a new middleware instance.
     *
     * @param  \Illuminate\Cache\RateLimiter  $limiter
     * @return void
     */
    public function __construct(RateLimiter $limiter)
    {
        $this->limiter = $limiter;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $key = 'password_change:'.($request->user() ? $request->user()->id : $request->ip());
        
        // Allow 5 attempts per minute
        if ($this->limiter->tooManyAttempts($key, 5)) {
            return response()->json([
                'message' => 'Too many password change attempts. Please try again later.',
                'retry_after' => $this->limiter->availableIn($key)
            ], 429);
        }
        
        $this->limiter->hit($key, 60);
        
        return $next($request);
    }
}