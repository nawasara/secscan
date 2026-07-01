<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->id();
            $table->string('finding_id', 32)->unique(); // sc_xxxxxxxx from agent
            $table->foreignId('agent_id')->constrained('nawasara_agents')->cascadeOnDelete();

            // What was found
            $table->string('path', 1024);                     // absolute file path on VM
            $table->string('signature_id', 64);               // e.g. ws_c99, bd_eval_base64
            $table->string('sig_name', 128);                  // human-readable
            $table->string('category', 32);                   // webshell | backdoor | exploit | integrity
            $table->string('severity', 16);                   // critical | high | medium
            $table->unsignedSmallInteger('score')->default(0);
            $table->text('description')->nullable();
            $table->text('matched_line')->nullable();         // up to 120-char snippet

            // File metadata at scan time
            $table->unsignedBigInteger('file_size')->nullable();
            $table->timestamp('file_mtime')->nullable();

            // Status workflow (same as findings: open → acknowledged → resolved | false_positive)
            $table->string('status', 32)->default('open');    // open | acknowledged | resolved | false_positive
            $table->foreignId('triaged_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('triaged_at')->nullable();
            $table->text('triage_note')->nullable();

            $table->timestamp('detected_at');
            $table->timestamps();

            // Composite index for the agent detail page query
            $table->index(['agent_id', 'status', 'detected_at']);
            $table->index(['severity', 'status']);
            $table->index('signature_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_agent_scan_findings');
    }
};
