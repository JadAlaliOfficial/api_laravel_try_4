<?php

namespace App\Http\Middleware;

use App\Services\TokenService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Sanctum\PersonalAccessToken;
use Symfony\Component\HttpFoundation\Response;

class RefreshTokenMiddleware
{
    protected TokenService $tokenService;

    public function __construct(TokenService $tokenService)
    {
        $this->tokenService = $tokenService;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Check if the user is authenticated
        if (!Auth::guard('sanctum')->check()) {
            return $next($request);
        }

        // Get the current token
        $accessToken = $request->user()->currentAccessToken();

        // Check if token is about to expire (less than 5 minutes remaining)
        if ($accessToken->expires_at && $accessToken->expires_at->subMinutes(5)->isPast()) {
            // Get refresh token from request header
            $refreshToken = $request->header('X-Refresh-Token');

            if ($refreshToken && $this->tokenService->isRefreshTokenValid($refreshToken)) {
                // Generate new tokens
                $tokens = $this->tokenService->refreshAccessToken($refreshToken, $accessToken->name, $accessToken->abilities ?? ['*']);

                if ($tokens) {
                    // Add the new tokens to the response headers
                    return $next($request)->withHeaders([
                        'X-New-Access-Token' => $tokens['access_token'],
                        'X-New-Refresh-Token' => $tokens['refresh_token'],
                        'X-Token-Expiration' => $tokens['expires_at'],
                    ]);
                }
            }
        }

        return $next($request);
    }
}