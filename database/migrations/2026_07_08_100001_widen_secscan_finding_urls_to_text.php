<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * scan_url stores the (possibly redirected) probed URL. Off-domain redirect
     * targets — e.g. Cloudflare Access login URLs carrying a JWT — routinely
     * exceed VARCHAR(255), which aborted the whole HTTP scan mid-run with
     * "Data too long for column 'scan_url'". Widen the URL columns to TEXT.
     * (Lesson from CLAUDE.md §13b: operator/network-supplied strings = TEXT.)
     */
    public function up(): void
    {
        Schema::table('nawasara_secscan_findings', function (Blueprint $table) {
            $table->text('scan_url')->nullable()->change();
            $table->text('site_url')->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_secscan_findings', function (Blueprint $table) {
            $table->string('scan_url')->nullable()->change();
            $table->string('site_url')->nullable()->change();
        });
    }
};
