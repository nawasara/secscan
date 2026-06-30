<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_agents', function (Blueprint $table) {
            $table->id();
            $table->string('agent_id', 32)->unique();
            $table->string('name');
            $table->string('hostname');
            $table->string('os', 64)->nullable();
            $table->string('arch', 16)->nullable();
            $table->string('agent_version', 32)->nullable();
            $table->string('web_server', 16)->nullable();
            $table->string('ip_local', 45)->nullable();
            $table->unsignedBigInteger('opd_id')->nullable();
            $table->string('api_key_hash');
            $table->string('status', 20)->default('never_connected'); // never_connected|online|offline
            $table->decimal('health_score', 5, 2)->default(100);
            $table->json('plugins_active')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamp('registered_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            $table->index('status');
            $table->index('opd_id');
            $table->index('last_seen_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_agents');
    }
};
