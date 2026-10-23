<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Inventaris versi PHP di ekosistem (pemantau versi PHP, Oktober 2026).
 *
 * Satu baris = satu sasaran yang terlihat dari satu sumber: hostname yang
 * dipindai dari luar, vhost di server WHM, atau runtime yang dilaporkan agen.
 * Sasaran yang sama boleh muncul dari dua sumber; keduanya dipertahankan
 * karena bisa berbeda (dari luar terlihat 8.2.30, dari dalam handler-nya
 * ea-php82).
 *
 * Tabel internal, tidak pernah dirujuk dari luar: id bigint.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_secscan_php_runtimes', function (Blueprint $table) {
            $table->id();
            $table->string('source', 16);              // external | whm | agent
            $table->string('target', 191);             // hostname, vhost, atau host/container
            // Instance WHM atau nama agen; '' untuk pindaian luar. Bukan NULL:
            // indeks unik menganggap dua NULL berbeda (lihat PhpRuntime::record).
            $table->string('origin', 191)->default('');
            $table->string('handler', 64)->nullable(); // ea-php81, docker:nama-container
            $table->string('php_version', 32)->nullable();
            $table->string('status', 16);              // safe | vulnerable | eol | hidden
            $table->string('detected_via', 32)->nullable();
            $table->boolean('exposes_version')->default(false);
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->timestamps();

            $table->unique(['source', 'target', 'origin'], 'secscan_php_runtime_unique');
            $table->index('status');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_secscan_php_runtimes');
    }
};
