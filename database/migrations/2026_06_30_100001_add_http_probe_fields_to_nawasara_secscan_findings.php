<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_secscan_findings', function (Blueprint $table) {
            // Source of this finding: 'sql' (F1 WordPress DB scan) or 'http' (F2 HTTP probe).
            // Nullable for backwards compat — existing rows are implicitly 'sql'.
            $table->string('scan_source', 8)->nullable()->default(null)->after('id');

            // For HTTP-source findings: the hostname and path that was probed.
            // db_name is kept as the grouping key for SQL findings; for HTTP findings
            // db_name stores the hostname so the unique index still works cleanly.
            $table->string('scan_path')->nullable()->after('site_url');

            // HTTP probe metadata stored in evidence, but we index the URL
            // separately for quick lookup / dedup.
            $table->string('scan_url')->nullable()->after('scan_path');

            // Drop the old unique index — it was (db_name, threat_type).
            // F2 needs (db_name, scan_path, threat_type) so HTTP probes per-path
            // don't collapse into one row per hostname.
            $table->dropUnique(['db_name', 'threat_type']);

            // New composite unique: one finding per (source_key, path, threat_type).
            // For SQL findings scan_path is null — MySQL treats (X, NULL, Y) as
            // distinct from (X, NULL, Z) even with null, so SQL rows still dedup
            // correctly by (db_name, threat_type). For HTTP rows scan_path is the
            // probed path, giving per-path dedup.
            $table->unique(['db_name', 'scan_path', 'threat_type'], 'secscan_findings_source_path_threat_unique');
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_secscan_findings', function (Blueprint $table) {
            $table->dropUnique('secscan_findings_source_path_threat_unique');
            $table->unique(['db_name', 'threat_type']);
            $table->dropColumn(['scan_source', 'scan_path', 'scan_url']);
        });
    }
};
