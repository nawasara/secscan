<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\PhpRuntime;
use Nawasara\Secscan\Services\PhpRuntimeScanner;
use Nawasara\Secscan\Support\PhpPatchLevels;

/**
 * Pemindaian harian versi PHP: dari luar lalu dari dalam WHM, kemudian satu
 * peringatan ringkasan.
 *
 * ⚠️ Satu peringatan per golongan, bukan per situs. Survei pertama
 * menemukan belasan situs sekaligus; per situs berarti belasan pesan
 * Telegram tiap pagi untuk masalah yang sama, dan orang berhenti
 * membacanya. target_id tetap ('summary'), sehingga peringatannya bisa
 * di-ack dan otomatis selesai saat jumlahnya nol.
 */
class ScanPhpRuntimesJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    public const RULE_VULNERABLE = 'secscan.php.vulnerable';

    public const RULE_EOL = 'secscan.php.eol';

    /** 274 hostname × 8 detik dalam kelompok 20, ditambah SSH ke tiap WHM. */
    public int $timeout = 600;

    public int $tries = 1;

    public function __construct(public string $triggerSource = 'scheduled') {}

    public function handle(): void
    {
        $scanner = new PhpRuntimeScanner(PhpPatchLevels::fromConfig());

        $external = $scanner->scanExternal();
        $whm = $scanner->scanWhm();

        Log::info('secscan.php_monitor.completed', [
            'trigger' => $this->triggerSource,
            'external' => $external,
            'whm' => $whm,
        ]);

        $this->alert(PhpPatchLevels::VULNERABLE, self::RULE_VULNERABLE);
        $this->alert(PhpPatchLevels::EOL, self::RULE_EOL);
    }

    protected function alert(string $status, string $rule): void
    {
        if (! class_exists(Alerter::class)) {
            return;
        }

        $targets = PhpRuntime::where('status', $status)
            ->orderBy('target')
            ->get(['target', 'php_version'])
            ->unique('target');

        try {
            if ($targets->isEmpty()) {
                Alerter::resolve($rule, 'PhpRuntime', 'summary');

                return;
            }

            $sample = $targets->take(8)
                ->map(fn ($r) => $r->target.' ('.($r->php_version ?? '?').')')
                ->implode(', ');

            Alerter::fire($rule, 'PhpRuntime', 'summary', [
                'count' => $targets->count(),
                'sample' => $sample.($targets->count() > 8 ? ', ...' : ''),
                'advisory' => (string) config('nawasara-secscan.php_monitor.advisory'),
                'url' => route('nawasara-secscan.php-runtimes'),
            ]);
        } catch (\Throwable $e) {
            Log::warning('secscan.php_monitor.alert_failed', ['rule' => $rule, 'error' => $e->getMessage()]);
        }
    }
}
