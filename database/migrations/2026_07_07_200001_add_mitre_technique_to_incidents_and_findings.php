<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            // MITRE ATT&CK technique ID, e.g. "T1110.001" or "T1505.003". Null
            // for exploit chains (multiple techniques) and legacy agent data.
            $table->string('mitre_technique', 16)->nullable()->after('type');
        });

        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->string('mitre_technique', 16)->nullable()->after('signature_id');
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->dropColumn('mitre_technique');
        });

        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->dropColumn('mitre_technique');
        });
    }
};
