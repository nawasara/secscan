<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_security_incidents', function (Blueprint $table) {
            $table->id();
            $table->string('incident_id', 32)->unique();
            $table->unsignedBigInteger('agent_id');
            $table->string('type', 64);
            $table->string('severity', 16); // info|medium|high|critical
            $table->string('source_ip', 45);
            $table->unsignedSmallInteger('score')->default(0);
            $table->boolean('correlated')->default(false);
            $table->string('correlated_group_id', 32)->nullable();
            $table->json('evidence');
            $table->json('metadata')->nullable();
            $table->timestamp('detected_at');
            $table->boolean('notified')->default(false);
            $table->timestamp('notified_at')->nullable();
            $table->timestamps();

            $table->foreign('agent_id')->references('id')->on('nawasara_agents')->cascadeOnDelete();
            $table->index(['agent_id', 'detected_at']);
            $table->index(['source_ip', 'detected_at']);
            $table->index(['severity', 'detected_at']);
            $table->index('type');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_security_incidents');
    }
};
