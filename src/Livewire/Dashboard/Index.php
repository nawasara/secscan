<?php

namespace Nawasara\Secscan\Livewire\Dashboard;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Nawasara\DatabaseMonitor\Services\MysqlConnection;
use Nawasara\Secscan\Jobs\ScanWordpressJob;
use Nawasara\Secscan\Models\SecscanFinding;

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
