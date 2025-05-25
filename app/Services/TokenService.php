<?php

namespace App\Services;

use App\Models\RefreshToken;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;
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
     * Create a new access token and refresh token for the user.
     *
     * @param User $user
     * @param string $tokenName
     * @param array $abilities
     * @return array
     */
    public function createTokens(User $user, string $tokenName = 'api', array $abilities = ['*']): array
    {
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
        // Delete existing tokens with the same name if needed
        // $user->tokens()->where('name', $tokenName)->delete();
        
        // Create new access token with expiration
        return $user->createToken(
            $tokenName,
            $abilities,
            Carbon::now()->addMinutes($this->accessTokenExpiration)
        );
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
     * Check if a refresh token is valid.
     *
     * @param string $refreshToken
     * @return bool
     */
    public function isRefreshTokenValid(string $refreshToken): bool
    {
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
        $this->refreshTokenExpiration = $minutes;
        return $this;
    }
}