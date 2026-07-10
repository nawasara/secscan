<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Audit trail + source of truth for every IP block the Decision Engine
        // (or an operator) makes. One row per block action; unblock stamps
        // unblocked_at and flips status rather than deleting, so history stays.
        Schema::create('nawasara_ip_blocks', function (Blueprint $table) {
            $table->id();
            $table->string('ip', 45)->index();
            $table->string('status', 16)->default('active'); // active | removed
            $table->string('reason', 64)->nullable();         // e.g. sql_injection
            $table->string('cf_rule_id', 64)->nullable();     // Cloudflare access-rule id (for unblock)
            $table->unsignedBigInteger('incident_id')->nullable(); // incident that triggered it
            $table->boolean('dry_run')->default(false);       // true = decided but NOT actually blocked on CF
            $table->text('notes')->nullable();                // CF notes tag + context
            $table->unsignedBigInteger('blocked_by')->nullable(); // null = automatic (Decision Engine)
            $table->unsignedBigInteger('unblocked_by')->nullable();
            $table->timestamp('blocked_at');
            $table->timestamp('unblocked_at')->nullable();
            $table->timestamps();

            // Fast "is this IP already actively blocked?" check in the engine.
            $table->index(['ip', 'status']);
            $table->index(['status', 'blocked_at']);
            $table->foreign('incident_id')->references('id')->on('nawasara_security_incidents')->nullOnDelete();
        });

        // Mark on the incident itself so the UI can badge "Blocked" and the
        // engine can skip re-evaluating an incident it already actioned.
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->timestamp('blocked_at')->nullable()->after('last_seen_at');
            $table->unsignedBigInteger('block_id')->nullable()->after('blocked_at'); // -> nawasara_ip_blocks.id
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->dropColumn(['blocked_at', 'block_id']);
        });
        Schema::dropIfExists('nawasara_ip_blocks');
    }
};
