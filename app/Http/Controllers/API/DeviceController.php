<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Services\TokenService;
use Illuminate\Http\Request;

class DeviceController extends Controller
{
    protected TokenService $tokenService;

    public function __construct(TokenService $tokenService)
    {
        $this->tokenService = $tokenService;
    }

    /**
     * Get all active devices/sessions for the authenticated user.
     *
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     */
    public function index(Request $request)
    {
        $devices = $this->tokenService->getUserDevices($request->user());
        
        return response()->json([
            'devices' => $devices,
            'current_device_id' => $request->user()->currentAccessToken()->id
        ]);
    }

    /**
     * Revoke a specific device token.
     *
     * @param Request $request
     * @param int $id
     * @return \Illuminate\Http\JsonResponse
     */
    public function destroy(Request $request, int $id)
    {
        // Don't allow revoking the current token
        if ($request->user()->currentAccessToken()->id === $id) {
            return response()->json([
                'message' => 'Cannot revoke the current device token. Use logout instead.'
            ], 400);
        }
        
        $revoked = $this->tokenService->revokeDeviceToken($request->user(), $id);
        
        if (!$revoked) {
            return response()->json([
                'message' => 'Device token not found or already revoked'
            ], 404);
        }
        
        return response()->json([
            'message' => 'Device token revoked successfully'
        ]);
    }
}