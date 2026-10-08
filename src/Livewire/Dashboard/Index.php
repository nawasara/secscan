<?php

namespace Nawasara\Secscan\Livewire\Dashboard;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Nawasara\DatabaseMonitor\Services\MysqlConnection;
use Nawasara\Secscan\Jobs\ScanWordpressJob;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecurityIncident;

class Index extends Component
{
    public function scanNow(): void
    {
        $this->authorize('secscan.scan.execute');

        ScanWordpressJob::dispatch(triggerSource: 'manual');

        $this->dispatch('toast', [
            'type' => 'info',
            'message' => 'Pemindaian dijalankan di latar belakang. Hasil muncul beberapa saat lagi.',
        ]);
    }

    #[Computed]
    public function isConfigured(): bool
    {
        return app(MysqlConnection::class)->isConfigured();
    }

    /** @return array<string,int> */
    #[Computed]
    public function stats(): array
    {
        $active = SecscanFinding::active();

        return [
            'critical' => (clone $active)->where('severity', SecscanFinding::SEVERITY_CRITICAL)->count(),
            'warning' => (clone $active)->where('severity', SecscanFinding::SEVERITY_WARNING)->count(),
            'open' => (clone $active)->where('status', SecscanFinding::STATUS_OPEN)->count(),
            'sites' => SecscanFinding::active()->distinct('db_name')->count('db_name'),
            // Selesai, but the database scan still finds the content (usually
            // a suspended cPanel account). Shown so the dirty databases are
            // cleaned before an account is reactivated.
            'still_in_db' => SecscanFinding::where('status', SecscanFinding::STATUS_RESOLVED)
                ->where(fn ($q) => $q->whereNull('scan_source')->orWhere('scan_source', 'sql'))
                ->whereColumn('last_detected_at', '>', 'resolved_at')
                ->count(),
        ];
    }

    /** @return array<string,int> */
    #[Computed]
    public function agentStats(): array
    {
        // Same online rule and same "today" (WIB) as the Agen page, so the
        // two never show different numbers for the same thing.
        return [
            'total'           => Agent::count(),
            'online'          => Agent::online()->count(),
            'offline'         => Agent::offline()->count(),
            'critical_today'  => SecurityIncident::where('severity', SecurityIncident::SEVERITY_CRITICAL)->today()->count(),
        ];
    }

    /** Most urgent active findings for the dashboard preview. */
    #[Computed]
    public function topFindings()
    {
        return SecscanFinding::active()
            ->orderByDesc('score')
            ->orderByDesc('last_detected_at')
            ->limit(10)
            ->get();
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.dashboard.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
