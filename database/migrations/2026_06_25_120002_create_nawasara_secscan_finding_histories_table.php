<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Append-only triage audit trail — one row per status transition
        // (e.g. open → acknowledged → false_positive). Pattern mirrors
        // nawasara-hibah StatusHistori.
        Schema::create('nawasara_secscan_finding_histories', function (Blueprint $table) {
            $table->id();
            $table->foreignId('finding_id')
                ->constrained('nawasara_secscan_findings')
                ->cascadeOnDelete();
            $table->string('status_from', 24)->nullable();
            $table->string('status_to', 24);
            $table->unsignedBigInteger('changed_by')->nullable();
            $table->text('reason')->nullable();
            $table->timestamp('created_at')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_secscan_finding_histories');
    }
};
