<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_agent_heartbeats', function (Blueprint $table) {
            $table->id();
            $table->unsignedBigInteger('agent_id');
            $table->string('agent_version', 32)->nullable();
            $table->decimal('health_score', 5, 2)->default(100);
            $table->unsignedSmallInteger('pending_incidents')->default(0);
            $table->json('plugins_active')->nullable();
            $table->json('metrics')->nullable(); // {cpu_percent, mem_used_mb, disk_used_percent}
            $table->unsignedInteger('uptime_seconds')->default(0);
            $table->timestamps();

            $table->foreign('agent_id')->references('id')->on('nawasara_agents')->cascadeOnDelete();
            $table->index(['agent_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_agent_heartbeats');
    }
};
