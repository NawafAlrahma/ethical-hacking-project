<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Auth\LoginController;
use App\Http\Controllers\TargetController;

// ------------------- AUTH -------------------

Route::get('/login', [LoginController::class, 'showLoginForm'])->name('login');
Route::post('/login', [LoginController::class, 'login'])->name('login.post');
Route::post('/logout', [LoginController::class, 'logout'])->name('logout');

// ------------------- PROTECTED -------------------

Route::middleware('auth')->group(function () {

    // Dashboard Redirect
    Route::get('/', function () {
        return redirect()->route('targets.index');
    });

    // Targets CRUD
    Route::get('/targets', [TargetController::class, 'index'])->name('targets.index');
    Route::get('/targets/create', [TargetController::class, 'create'])->name('targets.create');
    Route::post('/targets', [TargetController::class, 'store'])->name('targets.store');

    Route::get('/targets/{id}', [TargetController::class, 'show'])->name('targets.show');
    Route::delete('/targets/{id}', [TargetController::class, 'destroy'])->name('targets.destroy');

    // Recheck
    Route::get('/targets/{id}/recheck', [TargetController::class, 'recheck'])->name('targets.recheck');

    // Compare Findings
    Route::get('/targets/{id}/compare', [TargetController::class, 'compare'])->name('targets.compare');

});
