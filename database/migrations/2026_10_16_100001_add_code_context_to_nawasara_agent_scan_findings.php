<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Konteks kode di sekitar temuan pemindai berkas (agen >= v0.13.0).
 *
 * Sebelumnya hanya 120 karakter yang cocok yang tersimpan, sehingga temuan
 * seperti plugin yang menulis index.php-nya sendiri atau JS termampatkan
 * tidak dapat dibedakan dari webshell tanpa SSH ke server. Agen mengirim
 * ±15 baris (maks 4 KB) dengan nilai kredensial sudah disamarkan.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->text('matched_context')->nullable()->after('matched_line');
            $table->unsignedInteger('context_start_line')->nullable()->after('matched_context');
            $table->unsignedInteger('match_line')->nullable()->after('context_start_line');
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_agent_scan_findings', function (Blueprint $table) {
            $table->dropColumn(['matched_context', 'context_start_line', 'match_line']);
        });
    }
};
