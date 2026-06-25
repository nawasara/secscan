<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_secscan_findings', function (Blueprint $table) {
            $table->id();

            // Which monitored database this finding belongs to. Stored as the
            // raw schema name (not a FK) because the scanned databases are on
            // the remote server, not local rows — db_name is the natural key.
            $table->string('db_name', 191)->index();

            // Resolved site identity (best-effort from wp_options).
            $table->string('site_url')->nullable();
            $table->string('site_name')->nullable();

            // What kind of threat: judol | defaced | phishing | spam | malware.
            $table->string('threat_type', 32);

            // critical | warning | info — derived from score via config thresholds.
            $table->string('severity', 16)->default('info');

            // 0-100 weighted confidence.
            $table->unsignedSmallInteger('score')->default(0);

            // Triage state: open | acknowledged | false_positive | resolved.
            $table->string('status', 24)->default('open')->index();

            // Per-signal evidence (which checks fired, sample titles, counts).
            // JSON so the detail view can show exactly why it was flagged.
            $table->json('evidence')->nullable();

            $table->timestamp('first_detected_at')->nullable();
            $table->timestamp('last_detected_at')->nullable();

            // Triage audit fields.
            $table->unsignedBigInteger('acknowledged_by')->nullable();
            $table->timestamp('acknowledged_at')->nullable();
            $table->text('acknowledged_reason')->nullable();
            $table->unsignedBigInteger('resolved_by')->nullable();
            $table->timestamp('resolved_at')->nullable();
            $table->text('resolved_reason')->nullable();

            $table->timestamps();

            // One open finding per (db, threat_type) — the scanner upserts so a
            // recurring issue updates score/last_detected_at instead of piling
            // up duplicate rows. History is tracked separately.
            $table->unique(['db_name', 'threat_type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_secscan_findings');
    }
};
