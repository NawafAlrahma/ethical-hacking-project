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
Schema::create('targets', function (Blueprint $table) {
    $table->id();
    $table->string('type'); // ip / domain
    $table->string('value');
    $table->string('status')->default('pending');
    $table->string('verify_status')->default('pending');
    $table->string('recheck_status')->default('none');
    $table->timestamps();
});

    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('targets');
    }
};
