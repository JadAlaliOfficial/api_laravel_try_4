<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\DeviceController;
use App\Http\Middleware\DeviceInfoMiddleware;

// Public routes
// Public authentication endpoints
Route::post('/register', [AuthController::class, 'register'])->middleware(DeviceInfoMiddleware::class);
Route::post('/login', [AuthController::class, 'login'])->middleware(DeviceInfoMiddleware::class);

// Token refresh endpoint
Route::post('/refresh', [AuthController::class, 'refresh'])->middleware(DeviceInfoMiddleware::class);

// Protected routes
// Protected device management
Route::middleware(['auth:sanctum', DeviceInfoMiddleware::class])->group(function () {
    Route::get('/user', [AuthController::class, 'profile']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/revoke', [AuthController::class, 'revokeToken']);
    
    // Device management routes
    Route::get('/devices', [DeviceController::class, 'index']);
    Route::delete('/devices/{id}', [DeviceController::class, 'destroy']);
});

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');