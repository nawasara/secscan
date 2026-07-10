<?php

namespace Nawasara\Secscan;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Alerting\Models\AlertRule;
use Nawasara\DatabaseMonitor\Services\MysqlConnection;
use Nawasara\Secscan\Jobs\ScanHttpJob;
use Nawasara\Secscan\Jobs\ScanWordpressJob;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Services\FindingScorer;
use Nawasara\Secscan\Services\HtmlSignalDetector;
use Nawasara\Secscan\Services\SiteHttpFetcher;
use Nawasara\Secscan\Services\SqlSignalDetector;
use Symfony\Component\Finder\Finder;

class SecscanServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'nawasara-secscan');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        if (is_dir(__DIR__.'/../resources/views/components')) {
            Blade::anonymousComponentPath(__DIR__.'/../resources/views/components', 'nawasara-secscan');
        }

        $this->registerLivewire();
        $this->registerSchedule();
        $this->registerAlertRules();
    }

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/nawasara-secscan.php', 'nawasara-secscan');

        // SqlSignalDetector reuses database-monitor's read-only MySQL
        // connection (singleton) — no new credentials, READ ONLY enforced.
        $this->app->singleton(FindingScorer::class, fn () => new FindingScorer());
        $this->app->singleton(SqlSignalDetector::class, fn ($app) => new SqlSignalDetector(
            $app->make(MysqlConnection::class),
            $app->make(FindingScorer::class),
        ));

        // F2 services — singletons so rate-limit/backoff state persists per process.
        $this->app->singleton(SiteHttpFetcher::class, fn () => new SiteHttpFetcher());
        $this->app->singleton(HtmlSignalDetector::class, fn () => new HtmlSignalDetector());
    }

    /**
     * Two rules: compromised (critical — judol/malware/defaced/phishing) and
     * suspicious (warning — weaker signals). registerOrReplaceRule is
     * idempotent across hot reloads.
     */
    protected function registerAlertRules(): void
    {
        $cooldown = (int) config('nawasara-secscan.alerts.cooldown_minutes', 60);

        Alerter::registerOrReplaceRule(AlertRule::make([
            'key' => 'secscan.site.compromised',
            'severity' => 'critical',
            'category' => 'security',
            'cooldown_minutes' => $cooldown,
            'description' => 'Situs menunjukkan indikator kuat ter-kompromi (judol/malware/defacement)',
            'subject_template' => '[{severity}] {context.site_name} terindikasi {context.threat_type} (skor {context.score})',
        ]));

        Alerter::registerOrReplaceRule(AlertRule::make([
            'key' => 'secscan.site.suspicious',
            'severity' => 'warning',
            'category' => 'security',
            'cooldown_minutes' => $cooldown,
            'description' => 'Situs menunjukkan sinyal mencurigakan yang perlu verifikasi',
            'subject_template' => '[{severity}] {context.site_name} mencurigakan: {context.threat_type} (skor {context.score})',
        ]));

        // Fired by the Decision Engine when an attacker IP is auto-blocked at
        // the Cloudflare edge (or would be, in dry-run).
        Alerter::registerOrReplaceRule(AlertRule::make([
            'key' => 'secscan.ip.autoblocked',
            'severity' => 'warning',
            'category' => 'security',
            'cooldown_minutes' => 0, // each block is a distinct action worth notifying
            'description' => 'IP penyerang otomatis di-block di Cloudflare edge oleh Decision Engine',
            'subject_template' => '[auto-block] IP {context.ip} di-block ({context.reason}, skor {context.score})',
        ]));
    }

    /**
     * Schedule the hourly scan via $schedule->call() (NOT ->command()) —
     * package commands don't reliably surface in the Artisan kernel.
     * See reference_schedule_call_workaround.
     */
    protected function registerSchedule(): void
    {
        $this->app->booted(function () {
            if (! $this->app->runningInConsole()) {
                return;
            }
            if (! config('nawasara-secscan.scheduler.enabled', true)) {
                return;
            }

            $interval = max(1, min(60, (int) config('nawasara-secscan.scan_interval', 60)));
            $schedule = $this->app->make(Schedule::class);

            $schedule->call(function () {
                ScanWordpressJob::dispatch(triggerSource: 'scheduled');
            })
                ->name('nawasara-secscan:scan-wordpress')
                ->cron("*/{$interval} * * * *")
                ->withoutOverlapping(15);

            // Mark agents offline if no heartbeat in last 3 minutes.
            $schedule->call(function () {
                Agent::where('status', Agent::STATUS_ONLINE)
                    ->where('last_seen_at', '<', now()->subMinutes(3))
                    ->update(['status' => Agent::STATUS_OFFLINE]);
            })
                ->name('nawasara-secscan:check-agent-status')
                ->everyMinute()
                ->withoutOverlapping(2);

            // F2 HTTP probe — runs less frequently (default every 6 hours).
            // Config is in minutes; convert to hours for cron (min 1h, max 24h).
            if (config('nawasara-secscan.http_probe.enabled', true)) {
                $httpMinutes = max(60, (int) config('nawasara-secscan.http_probe.scan_interval', 360));
                $httpHours   = max(1, (int) round($httpMinutes / 60));
                $schedule->call(function () {
                    ScanHttpJob::dispatch(triggerSource: 'scheduled');
                })
                    ->name('nawasara-secscan:scan-http')
                    ->cron("0 */{$httpHours} * * *")
                    ->withoutOverlapping(30);
            }
        });
    }

    protected function registerLivewire(): void
    {
        $namespace = 'Nawasara\\Secscan\\Livewire';
        $basePath = __DIR__.'/Livewire';

        if (! is_dir($basePath)) {
            return;
        }

        $finder = new Finder();
        $finder->files()->in($basePath)->name('*.php');

        foreach ($finder as $file) {
            $relativePath = str_replace('/', '\\', $file->getRelativePathname());
            $class = $namespace.'\\'.Str::beforeLast($relativePath, '.php');

            if (class_exists($class)) {
                $alias = 'nawasara-secscan.'.
                    Str::of($relativePath)
                        ->replace('.php', '')
                        ->replace('\\', '.')
                        ->replace('/', '.')
                        ->explode('.')
                        ->map(fn ($segment) => Str::kebab($segment))
                        ->join('.');

                Livewire::component($alias, $class);
            }
        }
    }
}
