<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->string('source_ip', 45)->nullable()->change();
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_security_incidents', function (Blueprint $table) {
            $table->string('source_ip', 45)->nullable(false)->change();
        });
    }
};
