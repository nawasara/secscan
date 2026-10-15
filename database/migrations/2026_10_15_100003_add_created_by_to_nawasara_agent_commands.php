<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Siapa yang menerbitkan perintah agen.
 *
 * Audit keamanan 15 Oktober 2026, temuan R7: penerbit perintah dapat
 * menyetujui perintahnya sendiri (`restart_mysql`, `block_ip`), sehingga
 * "butuh persetujuan" tidak berarti apa-apa. Tanpa kolom ini aturan "tidak
 * boleh menyetujui perintah sendiri" tidak dapat diperiksa.
 *
 * Null untuk perintah lama dan perintah otomatis dari Decision Engine.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_agent_commands', function (Blueprint $table) {
            $table->foreignId('created_by')->nullable()->after('params')->constrained('users')->nullOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_agent_commands', function (Blueprint $table) {
            $table->dropConstrainedForeignId('created_by');
        });
    }
};
