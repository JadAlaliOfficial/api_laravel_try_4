<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->string('ip_address')->nullable()->after('expires_at');
            $table->string('user_agent')->nullable()->after('ip_address');
            $table->string('browser')->nullable()->after('user_agent');
            $table->string('platform')->nullable()->after('browser');
            $table->string('device')->nullable()->after('platform');
            $table->string('location')->nullable()->after('device');
            $table->string('country_code')->nullable()->after('location');
            $table->boolean('is_suspicious')->default(false)->after('country_code');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('personal_access_tokens', function (Blueprint $table) {
            $table->dropColumn([
                'ip_address',
                'user_agent',
                'browser',
                'platform',
                'device',
                'location',
                'country_code',
                'is_suspicious'
            ]);
        });
    }
};