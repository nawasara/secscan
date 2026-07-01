<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_agent_commands', function (Blueprint $table) {
            $table->id();
            $table->string('command_id', 32)->unique();   // random UUID sent to agent
            $table->foreignId('agent_id')->constrained('nawasara_agents')->cascadeOnDelete();

            $table->string('action', 64);                 // block_ip | unblock_ip | restart_nginx | ...
            $table->json('params')->nullable();           // e.g. {"ip":"1.2.3.4"}

            // Lifecycle: pending → approved/rejected → sent → completed/failed
            $table->enum('status', [
                'pending',    // waiting for admin approval
                'approved',   // approved, queued for agent poll
                'rejected',   // admin rejected
                'sent',       // agent has picked it up (claimed from /pending)
                'completed',  // agent reported success
                'failed',     // agent reported failure
            ])->default('pending');

            $table->text('output')->nullable();           // agent stdout
            $table->text('error')->nullable();            // agent error message

            $table->foreignId('approved_by')->nullable()->constrained('users')->nullOnDelete();
            $table->foreignId('rejected_by')->nullable()->constrained('users')->nullOnDelete();
            $table->text('rejection_reason')->nullable();

            $table->timestamp('approved_at')->nullable();
            $table->timestamp('rejected_at')->nullable();
            $table->timestamp('sent_at')->nullable();     // when agent claimed it
            $table->timestamp('exec_at')->nullable();     // when agent executed it
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_agent_commands');
    }
};
