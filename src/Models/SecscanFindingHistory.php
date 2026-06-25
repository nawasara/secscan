<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Append-only triage audit row. Records who moved a finding between statuses
 * and why. No updated_at (immutable).
 */
class SecscanFindingHistory extends Model
{
    protected $table = 'nawasara_secscan_finding_histories';

    public $timestamps = false;

    protected $guarded = [];

    protected $casts = [
        'created_at' => 'datetime',
    ];

    public function finding(): BelongsTo
    {
        return $this->belongsTo(SecscanFinding::class, 'finding_id');
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'changed_by');
    }
}
