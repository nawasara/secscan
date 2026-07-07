<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            // detected_at = first detection; last_seen_at = most recent re-detection
            $table->timestamp('last_seen_at')->nullable()->after('detected_at');
            $table->unsignedInteger('occurrences')->default(1)->after('score');

            // Aggregation lookup: same agent + type + source_ip within the window
            $table->index(['agent_id', 'type', 'source_ip', 'last_seen_at'], 'nsi_aggregation_idx');
        });

        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->timestamp('last_seen_at')->nullable()->after('detected_at');
        });

        DB::table('nawasara_security_incidents')
            ->whereNull('last_seen_at')
            ->update(['last_seen_at' => DB::raw('detected_at')]);

        DB::table('nawasara_agent_scan_findings')
            ->whereNull('last_seen_at')
            ->update(['last_seen_at' => DB::raw('detected_at')]);
    }

    public function down(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->dropIndex('nsi_aggregation_idx');
            $table->dropColumn(['last_seen_at', 'occurrences']);
        });

        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->dropColumn('last_seen_at');
        });
    }
};
