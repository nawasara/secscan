<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Token pendaftaran agen sekali pakai.
 *
 * Audit keamanan 15 Oktober 2026, temuan T1: POST /api/agent/register terbuka
 * untuk siapa pun, dan agen hasil daftar itu dapat mengirim insiden palsu yang
 * membuat Decision Engine memblokir IP sembarang di Cloudflare tingkat akun.
 *
 * Yang disimpan hanya SHA-256 token, bukan tokennya. Token hanya tampil sekali
 * di panel saat dibuat. SHA-256 (bukan bcrypt) cukup karena tokennya acak
 * 192 bit, dan memungkinkan pencarian langsung lewat indeks unik.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_agent_enrollment_tokens', function (Blueprint $table) {
            $table->id();
            $table->char('token_hash', 64)->unique();
            $table->string('label', 100)->nullable();
            $table->foreignId('created_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('expires_at');
            $table->timestamp('used_at')->nullable();
            $table->foreignId('used_by_agent_id')->nullable()->constrained('nawasara_agents')->nullOnDelete();
            $table->string('used_from_ip', 45)->nullable();
            $table->timestamp('revoked_at')->nullable();
            $table->foreignId('revoked_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamps();

            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_agent_enrollment_tokens');
    }
};
