<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Secscan\Http\Api\AgentStatusController;
use Nawasara\Secscan\Http\Api\FindingController;
use Nawasara\Secscan\Http\Api\IncidentController;
use Nawasara\Secscan\Http\Api\IpBlockController;
use Nawasara\Secscan\Http\Api\StatsController;

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

/*
| Endpoint baca lain — semuanya read-only. Aksi tulis untuk domain-domain ini
| (triase temuan, perintah ke agent, hapus agent) sengaja TIDAK diekspos:
| perintah agent adalah bidang kendali, dan triase perlu jejak audit "siapa
| mengubah apa" yang hanya dicatat lewat UI.
*/

// Insiden: serangan yang dideteksi agent.
Route::middleware('scope:secscan.incident.read')->group(function () {
    Route::get('/incidents', [IncidentController::class, 'index'])->name('incidents.index');
    Route::get('/incidents/{incidentId}', [IncidentController::class, 'show'])->name('incidents.show');
});

// Temuan situs: judol / deface / phishing di situs pemerintah.
Route::middleware('scope:secscan.finding.read')->group(function () {
    Route::get('/findings', [FindingController::class, 'index'])->name('findings.index');
    Route::get('/findings/{id}', [FindingController::class, 'show'])
        ->whereNumber('id')
        ->name('findings.show');
});

// Status agent: untuk monitoring "agent mana yang berhenti melapor".
Route::middleware('scope:secscan.agent.read')->group(function () {
    Route::get('/agents', [AgentStatusController::class, 'index'])->name('agents.index');
    Route::get('/agents/{agentId}', [AgentStatusController::class, 'show'])->name('agents.show');
});

// Statistik agregat, termasuk host yang paling sering jadi sasaran.
Route::middleware('scope:secscan.stats.read')->group(function () {
    Route::get('/stats', [StatsController::class, 'index'])->name('stats.index');
});
