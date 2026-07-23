<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Http\Api\IpBlockController;

/*
|--------------------------------------------------------------------------
| Secscan API routes
|--------------------------------------------------------------------------
| Di-mount oleh SecscanServiceProvider di prefix /api/v1/secscan dengan
| middleware group:
|   - api      (Laravel default)
|   - api.auth (Bearer/X-API-Key dari nawasara/api)
|   - api.log  (audit log — setiap block/unblock via API tercatat)
|
| Per-route ditambah middleware scope:<name>. Block IP adalah aksi TULIS
| yang menyentuh Cloudflare edge sungguhan, jadi scope-nya dipisah:
|   - secscan.ipblock.read   → list + detail (aman, read-only)
|   - secscan.ipblock.write  → block IP baru (push ke CF)
|   - secscan.ipblock.delete → buka blokir
|
| Endpoint write/delete memakai CloudflareBlockService + IpBlock yang sama
| dengan auto-block Decision Engine, jadi hasilnya konsisten: muncul di
| dashboard IP Blocks, ter-audit, dan menghormati flag dry_run global.
*/

// Read: daftar + detail IP terblokir.
Route::middleware('scope:secscan.ipblock.read')->group(function () {
    Route::get('/ip-blocks', [IpBlockController::class, 'index'])->name('ip-blocks.index');
    Route::get('/ip-blocks/{ip}', [IpBlockController::class, 'show'])->name('ip-blocks.show');
});

// Write: block IP baru.
Route::middleware('scope:secscan.ipblock.write')->group(function () {
    Route::post('/ip-blocks', [IpBlockController::class, 'store'])->name('ip-blocks.store');
});

// Delete: buka blokir.
Route::middleware('scope:secscan.ipblock.delete')->group(function () {
    Route::delete('/ip-blocks/{ip}', [IpBlockController::class, 'destroy'])->name('ip-blocks.destroy');
});
