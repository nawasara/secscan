<?php

namespace Nawasara\Secscan\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Str;

class AgentCommand extends Model
{
    protected $table = 'nawasara_agent_commands';

    protected $fillable = [
        'command_id', 'agent_id', 'action', 'params', 'status',
        'output', 'error',
        'approved_by', 'rejected_by', 'rejection_reason',
        'approved_at', 'rejected_at', 'sent_at', 'exec_at',
    ];

    protected $casts = [
        'params'      => 'array',
        'approved_at' => 'datetime',
        'rejected_at' => 'datetime',
        'sent_at'     => 'datetime',
        'exec_at'     => 'datetime',
    ];

    const STATUS_PENDING   = 'pending';
    const STATUS_APPROVED  = 'approved';
    const STATUS_REJECTED  = 'rejected';
    const STATUS_SENT      = 'sent';
    const STATUS_COMPLETED = 'completed';
    const STATUS_FAILED    = 'failed';

    public static function boot(): void
    {
        parent::boot();
        static::creating(function ($model) {
            if (empty($model->command_id)) {
                $model->command_id = Str::random(32);
            }
        });
    }

    public function agent(): BelongsTo
    {
        return $this->belongsTo(Agent::class, 'agent_id');
    }

    public function approvedBy(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'approved_by');
    }

    public function rejectedBy(): BelongsTo
    {
        return $this->belongsTo(\App\Models\User::class, 'rejected_by');
    }

    public function isPending(): bool
    {
        return $this->status === self::STATUS_PENDING;
    }

    public function isApproved(): bool
    {
        return $this->status === self::STATUS_APPROVED;
    }

    public function statusColor(): string
    {
        return match ($this->status) {
            self::STATUS_PENDING   => 'warning',
            self::STATUS_APPROVED  => 'info',
            self::STATUS_REJECTED  => 'neutral',
            self::STATUS_SENT      => 'info',
            self::STATUS_COMPLETED => 'success',
            self::STATUS_FAILED    => 'danger',
            default                => 'neutral',
        };
    }

    public function statusLabel(): string
    {
        return match ($this->status) {
            self::STATUS_PENDING   => 'Menunggu Approval',
            self::STATUS_APPROVED  => 'Disetujui',
            self::STATUS_REJECTED  => 'Ditolak',
            self::STATUS_SENT      => 'Dikirim ke Agent',
            self::STATUS_COMPLETED => 'Selesai',
            self::STATUS_FAILED    => 'Gagal',
            default                => $this->status,
        };
    }

    public function actionLabel(): string
    {
        return match ($this->action) {
            'block_ip'               => 'Block IP',
            'unblock_ip'             => 'Unblock IP',
            'restart_nginx'          => 'Restart Nginx',
            'reload_nginx'           => 'Reload Nginx',
            'restart_apache'         => 'Restart Apache',
            'reload_apache'          => 'Reload Apache',
            'restart_php_fpm'        => 'Restart PHP-FPM',
            'reload_php_fpm'         => 'Reload PHP-FPM',
            'restart_mysql'          => 'Restart MySQL',
            'artisan_queue_restart'  => 'Artisan queue:restart',
            'artisan_optimize_clear' => 'Artisan optimize:clear',
            default                  => $this->action,
        };
    }

    public function isDestructive(): bool
    {
        return in_array($this->action, ['block_ip', 'restart_mysql', 'restart_php_fpm'], true);
    }
}
