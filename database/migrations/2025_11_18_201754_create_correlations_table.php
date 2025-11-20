<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
Schema::create('correlations', function (Blueprint $table) {
    $table->id();
    $table->unsignedBigInteger('target_id');
    $table->string('vuln_name');
    $table->string('cve_id')->nullable();
    $table->string('severity')->nullable();
    $table->float('score')->nullable();
    $table->text('evidence')->nullable();
    $table->text('description')->nullable();
    $table->text('recommendation')->nullable();
    $table->text('ai_exploit_pseudo_code')->nullable();
    $table->text('ai_enhanced_recommendation')->nullable();
    $table->timestamps();
});

    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('correlations');
    }
};
