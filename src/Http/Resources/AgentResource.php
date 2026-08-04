<?php

namespace Nawasara\Secscan\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nawasara\Secscan\Models\Agent;

/**
 * Transformer status agent untuk public API — **status kesehatan, bukan profil
 * mesin**. Cukup untuk monitoring eksternal ("agent mana yang mati?"), tidak
 * cukup untuk memetakan infrastruktur.
 *
 * Yang sengaja DIBLOK dan alasannya:
 *
 *   - `api_key_hash` — kredensial agent. Tidak pernah keluar ke mana pun.
 *   - `ip_local` — IP privat server OPD. Bocor = peta jaringan internal.
 *   - `hostname` — nama host internal, bernilai untuk pengintaian.
 *   - `agent_version`, `web_server`, `os`, `arch`, `plugins_active` —
 *     fingerprint attack-surface. Satu per satu terlihat sepele; digabung
 *     menjadi "server X menjalankan nginx di Ubuntu 20.04 dengan plugin ssh",
 *     yaitu daftar belanja bagi penyerang yang mencari versi rentan.
 *
 * @mixin Agent
 */
class AgentResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'agent_id' => $this->agent_id,
            'name' => $this->name,

            'status' => $this->status,              // never_connected | online | offline
            'status_label' => $this->statusLabel(),

            // 0–100. Dihitung agent sendiri dari kondisi host; angka agregat,
            // tanpa detail metrik mentah (CPU/disk) yang bisa memberi tahu
            // kapan sebuah server sedang lemah.
            'health_score' => $this->health_score !== null ? (float) $this->health_score : null,

            'last_seen_at' => $this->last_seen_at?->toIso8601String(),
            'registered_at' => $this->registered_at?->toIso8601String(),

            // Jumlah insiden — hanya kalau pemanggil memintanya lewat
            // withCount, supaya endpoint list tidak membayar query per baris.
            'incidents_count' => $this->when(
                $this->incidents_count !== null,
                fn () => (int) $this->incidents_count,
            ),
        ];
    }
}
