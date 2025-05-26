<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Jenssegers\Agent\Agent;
use Illuminate\Support\Facades\Log;

class DeviceInfoMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Only process if we have a user agent
        if ($request->header('User-Agent')) {
            $agent = new Agent();
            $agent->setUserAgent($request->header('User-Agent'));
            
            // Store device info in the request for later use
            $request->merge([
                'device_info' => [
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->header('User-Agent'),
                    'browser' => $agent->browser(),
                    'browser_version' => $agent->version($agent->browser()),
                    'platform' => $agent->platform(),
                    'platform_version' => $agent->version($agent->platform()),
                    'device' => $agent->device(),
                    'is_desktop' => $agent->isDesktop(),
                    'is_phone' => $agent->isPhone(),
                    'is_tablet' => $agent->isTablet(),
                ]
            ]);
        }
        

        return $next($request);
    }
}