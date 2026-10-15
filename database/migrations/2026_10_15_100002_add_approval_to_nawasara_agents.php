<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/**
 * Status persetujuan agen.
 *
 * Audit keamanan 15 Oktober 2026, temuan T1: agen yang baru mendaftar
 * berstatus `pending`. Insidennya tetap tersimpan dan terlihat di panel,
 * tetapi tidak masuk Decision Engine (tidak dapat memicu blokir IP) dan agen
 * tidak menerima perintah sampai admin menyetujuinya.
 *
 * Agen yang SUDAH ada di produksi (sekitar 5, sudah berjalan dengan api key
 * masing-masing) dianggap disetujui: mereka didaftarkan oleh tim sendiri
 * sebelum aturan ini ada, dan menahannya berarti mematikan auto-block
 * semalaman. Baris yang sudah dicabut (soft delete) ikut ditandai, tetapi
 * tetap tidak berpengaruh karena Decision Engine menolak agen yang dicabut.
 *
 * Kolom bawaan `pending` supaya baris baru yang lupa diisi status jatuh ke
 * keadaan aman, bukan ke `approved`.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_agents', function (Blueprint $table) {
            $table->string('approval_status', 16)->default('pending')->after('status');
            $table->foreignId('approved_by')->nullable()->after('approval_status')->constrained('users')->nullOnDelete();
            $table->timestamp('approved_at')->nullable()->after('approved_by');
            $table->unsignedBigInteger('enrollment_token_id')->nullable()->after('approved_at');

            $table->index('approval_status');
        });

        DB::table('nawasara_agents')->update([
            'approval_status' => 'approved',
            'approved_at' => now(),
        ]);
    }

    public function down(): void
    {
        Schema::table('nawasara_agents', function (Blueprint $table) {
            $table->dropIndex(['approval_status']);
            $table->dropConstrainedForeignId('approved_by');
            $table->dropColumn(['approval_status', 'approved_at', 'enrollment_token_id']);
        });
    }
};
