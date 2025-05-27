<?php

namespace App\Observers;

use App\Models\User;
use App\Models\RefreshToken;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Notification;
use App\Notifications\PasswordChanged;

class UserObserver
{
    /**
     * Handle the User "updated" event.
     */
    public function updated(User $user): void
    {
        // Check if password was changed
        if ($user->isDirty('password')) {
            // Revoke all access tokens
            $user->tokens()->delete();
            
            // Revoke all refresh tokens
            RefreshToken::where('user_id', $user->id)
                ->update(['revoked' => true]);
                
            // Send password change notification
            // $user->notify(new PasswordChanged());
        }
    }
}