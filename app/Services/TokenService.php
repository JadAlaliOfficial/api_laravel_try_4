<?php

namespace App\Services;

use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Sanctum\NewAccessToken;
use Laravel\Sanctum\PersonalAccessToken;

class TokenService
{
    /**
     * Default access token expiration in minutes
     */
    protected int $accessTokenExpiration = 60; // 1 hour

    /**
     * Default refresh token expiration in minutes
     */
    protected int $refreshTokenExpiration = 20160; // 14 days
    
    /**
     * The current request instance.
     */
    protected Request $request;
    
    /**
     * Constructor with request dependency injection
     */
    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    
    /**
     * Create a new access token and refresh token for the user.
     *
     * @param User $user
     * @param string $tokenName
     * @param array $abilities
     * @return array
     */
    public function createTokens(User $user, string $tokenName = 'api', array $abilities = ['*']): array
    {
        Log::debug("create tokens");
        // Begin a transaction to ensure both tokens are created or none
        return DB::transaction(function () use ($user, $tokenName, $abilities) {
            // Create access token
            $accessToken = $this->createAccessToken($user, $tokenName, $abilities);
            
            // Create refresh token
            $refreshToken = $this->createRefreshToken($user, $accessToken->accessToken->id);
            
        
            return [
                'access_token' => $accessToken->plainTextToken,
                'refresh_token' => $refreshToken->token,
                'token_type' => 'Bearer',
                'expires_at' => Carbon::now()->addMinutes($this->accessTokenExpiration)->toDateTimeString(),
            ];
        });
    }

    /**
     * Create a new access token for the user.
     *
     * @param User $user
     * @param string $tokenName
     * @param array $abilities
     * @return NewAccessToken
     */
    protected function createAccessToken(User $user, string $tokenName, array $abilities): NewAccessToken
    {
        Log::debug("create access token");
        // Create new access token with expiration
        $token = $user->createToken(
            $tokenName,
            $abilities,
            Carbon::now()->addMinutes($this->accessTokenExpiration)
        );
        
        // Add device information to the token if available
        if ($this->request->has('device_info')) {
            $deviceInfo = $this->request->get('device_info');
            Log::debug($deviceInfo);
            $isSuspicious = $this->detectSuspiciousLogin($user, $deviceInfo);
            Log::debug($isSuspicious);
            // Get the location information using a geolocation service
            $locationInfo = $this->getLocationFromIp($deviceInfo['ip_address']);
            Log::debug($locationInfo);
            // Update the token with device information
            $accessTokenModel = $token->accessToken->fresh();
            Log::debug($deviceInfo['ip_address']);
            $accessTokenModel->update([
                'ip_address' => $this->request->ip(),
                'user_agent' => $deviceInfo['user_agent'],
                'browser' => $deviceInfo['browser'],
                'platform' => $deviceInfo['platform'],
                'device' => $deviceInfo['is_desktop'] ? 'Desktop' : 
                           ($deviceInfo['is_phone'] ? 'Phone' : 
                           ($deviceInfo['is_tablet'] ? 'Tablet' : 'Unknown')),
                'location' => $locationInfo['location'] ?? null,
                'country_code' => $locationInfo['country_code'] ?? null,
                'is_suspicious' => $isSuspicious,
            ]);
            Log::debug($accessTokenModel);
        }
        return $token;
    }

    /**
     * Create a new refresh token for the user.
     *
     * @param User $user
     * @param int $accessTokenId
     * @return RefreshToken
     */
    protected function createRefreshToken(User $user, int $accessTokenId): RefreshToken
    {
        Log::debug("create refresh token");
        // Generate a unique token
        $token = Str::random(80);
        
        // Create refresh token record
        return RefreshToken::create([
            'user_id' => $user->id,
            'token' => $token,
            'access_token_id' => $accessTokenId,
            'expires_at' => Carbon::now()->addMinutes($this->refreshTokenExpiration),
        ]);
    }

    /**
     * Refresh the access token using a valid refresh token.
     *
     * @param string $refreshToken
     * @param string $tokenName
     * @param array $abilities
     * @return array|null
     */
    public function refreshAccessToken(string $refreshToken, string $tokenName = 'api', array $abilities = ['*']): ?array
    {
        Log::debug("refresh access token");
        // Find the refresh token
        $refreshTokenModel = RefreshToken::where('token', $refreshToken)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->first();
        
        if (!$refreshTokenModel) {
            return null; // Invalid or expired refresh token
        }
        
        return DB::transaction(function () use ($refreshTokenModel, $tokenName, $abilities) {
            // Get the user
            $user = $refreshTokenModel->user;
            
            // Revoke the old access token if it exists
            if ($refreshTokenModel->access_token_id) {
                PersonalAccessToken::find($refreshTokenModel->access_token_id)?->delete();
            }
            
            // Revoke the old refresh token
            $refreshTokenModel->update(['revoked' => true]);
            
            // Create new tokens
            return $this->createTokens($user, $tokenName, $abilities);
        });
    }

    /**
     * Revoke a refresh token.
     *
     * @param string $refreshToken
     * @return bool
     */
    public function revokeRefreshToken(string $refreshToken): bool
    {
        Log::debug("revoke refresh token");
        $token = RefreshToken::where('token', $refreshToken)
            ->where('revoked', false)
            ->first();
        
        if (!$token) {
            return false;
        }
        
        // Revoke the associated access token if it exists
        if ($token->access_token_id) {
            PersonalAccessToken::find($token->access_token_id)?->delete();
        }
        
        // Revoke the refresh token
        return $token->update(['revoked' => true]);
    }
    
    /**
     * Revoke a specific device token by ID.
     *
     * @param User $user
     * @param int $tokenId
     * @return bool
     */
    public function revokeDeviceToken(User $user, int $tokenId): bool
    {
        Log::debug("revoke device token");
        $token = $user->tokens()->find($tokenId);
        
        if (!$token) {
            return false;
        }
        
        // Find and revoke any associated refresh tokens
        RefreshToken::where('access_token_id', $token->id)
            ->where('revoked', false)
            ->update(['revoked' => true]);
            
        // Delete the access token
        return (bool) $token->delete();
    }
    
    /**
     * Get all active devices/sessions for a user.
     *
     * @param User $user
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function getUserDevices(User $user)
    {
        Log::debug("get user devices");
        return $user->tokens()
            ->where('expires_at', '>', now())
            ->select([
                'id',
                'name',
                'ip_address',
                'browser',
                'platform',
                'device',
                'location',
                'country_code',
                'last_used_at',
                'created_at',
                'is_suspicious'
            ])
            ->orderBy('last_used_at', 'desc')
            ->get();
    }

    /**
     * Check if a refresh token is valid.
     *
     * @param string $refreshToken
     * @return bool
     */
    public function isRefreshTokenValid(string $refreshToken): bool
    {
        Log::debug("is refresh token valid");
        return RefreshToken::where('token', $refreshToken)
            ->where('revoked', false)
            ->where('expires_at', '>', now())
            ->exists();
    }

    /**
     * Set the access token expiration time in minutes.
     *
     * @param int $minutes
     * @return self
     */
    public function setAccessTokenExpiration(int $minutes): self
    {
        Log::debug("set access token expiration");
        $this->accessTokenExpiration = $minutes;
        return $this;
    }

    /**
     * Set the refresh token expiration time in minutes.
     *
     * @param int $minutes
     * @return self
     */
    public function setRefreshTokenExpiration(int $minutes): self
    {
        Log::debug("set refresh token expiration");
        $this->refreshTokenExpiration = $minutes;
        return $this;
    }
    
    /**
     * Detect suspicious login based on user's previous login patterns.
     *
     * @param User $user
     * @param array $deviceInfo
     * @return bool
     */
    protected function detectSuspiciousLogin(User $user, array $deviceInfo): bool
    {
        Log::debug("detect suspicious login");
        // Get the user's last used token with location info
        $lastToken = $user->tokens()
            ->whereNotNull('country_code')
            ->orderBy('last_used_at', 'desc')
            ->first();
            
        if (!$lastToken) {
            return false; // No previous login to compare with
        }
        
        // Get location info for current IP
        $locationInfo = $this->getLocationFromIp($deviceInfo['ip_address']);
        $currentCountry = $locationInfo['country_code'] ?? null;
        
        if (!$currentCountry) {
            return false; // Can't determine current country
        }
        
        // Check if country has changed
        if ($lastToken->country_code !== $currentCountry) {
            return true; // Different country = suspicious
        }
        
        // Check if device type has changed dramatically
        $lastDevice = $lastToken->device;
        $currentDevice = $deviceInfo['is_desktop'] ? 'Desktop' : 
                        ($deviceInfo['is_phone'] ? 'Phone' : 
                        ($deviceInfo['is_tablet'] ? 'Tablet' : 'Unknown'));
                        
        if ($lastDevice !== $currentDevice && $lastDevice !== 'Unknown' && $currentDevice !== 'Unknown') {
            return true; // Different device type = suspicious
        }
        
        return false;
    }
    
    /**
     * Get location information from IP address.
     * 
     * @param string $ip
     * @return array
     */
    protected function getLocationFromIp(string $ip): array
    {
        Log::debug("get location from ip");
        // For local development, return dummy data
        if (in_array($ip, ['127.0.0.1', '::1', 'localhost'])) {
            return [
                'country_code' => 'LOCAL',
                'location' => 'Local Development'
            ];
        }
        
        // In a real application, you would use a geolocation service like MaxMind GeoIP or ipinfo.io
        // Example with ipinfo.io:
        // $response = Http::get("https://ipinfo.io/{$ip}/json");
        // return [
        //     'country_code' => $response->json('country'),
        //     'location' => $response->json('city') . ', ' . $response->json('region')
        // ];
        
        // For this example, we'll return a placeholder
        // In production, implement a real IP geolocation service
        return [
            'country_code' => 'US',
            'location' => 'Unknown Location'
        ];
    }
}