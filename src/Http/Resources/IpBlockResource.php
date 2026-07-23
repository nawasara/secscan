<?php

namespace Nawasara\Secscan\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Nawasara\Secscan\Models\IpBlock;

/**
 * Transformer IP block untuk public API. **Eksplisit listkan field** yang
 * di-expose. `notes` dan `cf_rule_id` internal (memuat prefix audit + id token
 * + handle Cloudflare) TIDAK ikut — client cukup tahu status blokirnya.
 *
 * @mixin IpBlock
 */
class IpBlockResource extends JsonResource
{
    public function toArray(Request $request): array
    {
        return [
            'ip'      => $this->ip,
            'status'  => $this->status,          // active | removed
            'reason'  => $this->reason,

            // dry_run true = keputusan block dicatat tapi TIDAK benar-benar
            // di-push ke Cloudflare. Penting dibedakan: "tercatat" != "ditegakkan".
            'enforced' => ! $this->dry_run && $this->status === IpBlock::STATUS_ACTIVE,
            'dry_run'  => (bool) $this->dry_run,

            'blocked_at'   => $this->blocked_at?->toIso8601String(),
            'unblocked_at' => $this->unblocked_at?->toIso8601String(),

            // Insiden pemicu, kalau block ini otomatis dari Decision Engine.
            // null untuk block manual via API.
            'incident_id' => $this->incident_id,
        ];
    }
}
