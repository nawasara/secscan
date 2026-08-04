<?php

namespace Nawasara\Secscan\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nawasara\Secscan\Models\SecscanFinding;

/**
 * Transformer temuan situs untuk public API — situs pemerintah yang terindikasi
 * judi online, deface, phishing, dan sejenisnya.
 *
 * URL situs memang sudah publik, jadi mengeksposnya tidak menambah risiko. Yang
 * sengaja DIBLOK:
 *
 *   - `evidence` — memuat `accounts.recent_admin_list` dan
 *     `non_gov_email_admins`, yaitu daftar akun admin WordPress beserta
 *     alamat email. Itu PII, dan sekaligus daftar sasaran phishing yang rapi.
 *     Juga memuat cuplikan isi halaman yang disusupi.
 *   - `db_name` — nama schema database di server bersama. Nama objek
 *     infrastruktur internal; berguna hanya untuk enumerasi.
 *   - `scan_path` — path internal yang diperiksa scanner.
 *   - `acknowledged_by` / `resolved_by` / alasan triase — jejak audit internal
 *     tentang siapa di tim melakukan apa.
 *
 * @mixin SecscanFinding
 */
class FindingResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,

            // Nama situs yang bisa dibaca manusia. displayName() sudah memilih
            // antara site_name dan fallback, jadi konsumen tidak perlu tahu
            // kolom mana yang terisi.
            'site' => $this->displayName(),
            'site_url' => $this->site_url,

            // URL persis yang memicu temuan — publik, dan justru yang paling
            // dibutuhkan konsumen untuk memverifikasi sendiri.
            'scan_url' => $this->scan_url,

            'threat_type' => $this->threat_type,
            'threat_label' => SecscanFinding::threatLabels()[$this->threat_type] ?? $this->threat_type,

            'severity' => $this->severity,
            'score' => (int) $this->score,

            'status' => $this->status,              // open | acknowledged | false_positive | resolved
            'status_label' => SecscanFinding::statusLabels()[$this->status] ?? $this->status,

            // Sumber deteksi: 'sql' (inspeksi database WordPress) atau 'http'
            // (probe halaman). Membantu konsumen menilai keyakinan temuan.
            'scan_source' => $this->scan_source,

            'first_detected_at' => $this->first_detected_at?->toIso8601String(),
            'last_detected_at' => $this->last_detected_at?->toIso8601String(),
        ];
    }
}
