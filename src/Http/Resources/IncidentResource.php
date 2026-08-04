<?php

namespace Nawasara\Secscan\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nawasara\Secscan\Models\SecurityIncident;

/**
 * Transformer insiden keamanan untuk public API. **Eksplisit listkan field**
 * yang di-expose.
 *
 * Yang sengaja DIBLOK dan alasannya:
 *
 *   - `evidence` — baris log mentah. Sebuah request line utuh bisa memuat query
 *     string dengan token atau session id, user-agent, username SSH yang dicoba,
 *     dan payload serangan apa adanya (SQLi/XSS). Meneruskannya ke konsumen API
 *     berarti meneruskan data yang tidak pernah kita periksa isinya.
 *   - `metadata` — blob bebas dari agent, hanya divalidasi `nullable|array`.
 *     Isinya tidak terkendali, jadi tidak bisa dijamin aman.
 *   - `correlated_group_id` — internal, tidak bermakna di luar.
 *
 * Agent hanya diekspos sebagai nama. Hostname, IP internal, versi agent, dan
 * daftar plugin adalah fingerprint attack-surface — gabungannya memberi tahu
 * penyerang persis apa yang berjalan di server mana.
 *
 * @mixin SecurityIncident
 */
class IncidentResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'incident_id' => $this->incident_id,

            'type' => $this->type,
            'type_label' => $this->typeLabel(),
            'severity' => $this->severity,
            'score' => (int) $this->score,

            // IP penyerang — data utama yang berguna bagi konsumen (korelasi
            // dengan threat intel, blocklist sendiri, dsb).
            'source_ip' => $this->source_ip,

            // Berapa kali pola ini terulang dalam jendela agregasi
            // (config agent.incident_aggregation_hours, default 24 jam).
            'occurrences' => (int) $this->occurrences,
            'correlated' => (bool) $this->correlated,

            // Klasifikasi MITRE ATT&CK — standar lintas-organisasi, aman dan
            // justru memudahkan konsumen memetakan ke sistem mereka.
            'mitre_technique' => $this->mitre_technique,
            'mitre_name' => $this->mitre_technique ? $this->mitreName() : null,

            // Sasaran: nama vhost milik kita yang diserang. Diambil dari
            // evidence, TAPI hanya field host-nya — sisa isi evidence tidak
            // pernah ikut. Berguna untuk tahu situs mana yang jadi target.
            'targets' => $this->targetHosts(),

            'detected_at' => $this->detected_at?->toIso8601String(),
            'last_seen_at' => $this->last_seen_at?->toIso8601String(),

            // Apakah insiden ini berujung block di Cloudflare.
            'blocked' => $this->blocked_at !== null,
            'blocked_at' => $this->blocked_at?->toIso8601String(),

            // Nama agent pelapor saja — tanpa hostname/IP internal.
            'agent' => $this->whenLoaded('agent', fn () => [
                'agent_id' => $this->agent?->agent_id,
                'name' => $this->agent?->name,
            ]),
        ];
    }

    /**
     * Nama host yang jadi sasaran, unik, diambil dari evidence.
     *
     * Hanya key `host` yang dibaca; baris log mentah di entry yang sama tidak
     * disentuh. Dibatasi 5 supaya satu insiden dengan banyak bukti tidak
     * membengkakkan response.
     *
     * @return array<int, string>
     */
    protected function targetHosts(): array
    {
        $hosts = [];

        foreach ((array) ($this->evidence ?? []) as $entry) {
            $host = is_array($entry) ? ($entry['host'] ?? null) : null;

            if (is_string($host) && $host !== '' && ! in_array($host, $hosts, true)) {
                $hosts[] = $host;
            }
        }

        return array_slice($hosts, 0, 5);
    }
}
