<?php

namespace Nawasara\Secscan\Livewire\IpTimeline;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Show extends Component
{
    use HasTimeWindow;

    public string $ip = '';

    public function mount(string $ip): void
    {
        $this->ip = $ip;
        $this->authorize('secscan.view');
    }

    /**
     * Users land here to review an attacker IP's full history, so default
     * to 'all'; the time-window pills let them narrow to a period.
     */
    protected function defaultTimeWindow(): string
    {
        return 'all';
    }

    #[Computed]
    public function incidents()
    {
        return SecurityIncident::with('agent')
            ->where('source_ip', $this->ip)
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'detected_at'))
            ->orderByDesc('detected_at')
            ->limit(500) // guard: a very active IP shouldn't render unbounded rows
            ->get();
    }

    /**
     * Summary is computed straight from the DB (not the capped/windowed
     * timeline collection) so first_seen / total stay accurate all-time,
     * independent of the active time-window.
     */
    #[Computed]
    public function summary(): array
    {
        $row = SecurityIncident::where('source_ip', $this->ip)
            ->selectRaw('COUNT(*) as total')
            ->selectRaw("SUM(severity = ?) as critical", [SecurityIncident::SEVERITY_CRITICAL])
            ->selectRaw("SUM(severity = ?) as high", [SecurityIncident::SEVERITY_HIGH])
            ->selectRaw('COUNT(DISTINCT agent_id) as agents')
            ->selectRaw('MIN(detected_at) as first_seen')
            ->selectRaw('MAX(detected_at) as last_seen')
            ->selectRaw('SUM(correlated = 1) as correlated')
            ->first();

        return [
            'total'      => (int) ($row->total ?? 0),
            'critical'   => (int) ($row->critical ?? 0),
            'high'       => (int) ($row->high ?? 0),
            'agents'     => (int) ($row->agents ?? 0),
            'first_seen' => $row->first_seen,
            'last_seen'  => $row->last_seen,
            'correlated' => (int) ($row->correlated ?? 0),
        ];
    }

    #[Computed]
    public function agentNames(): array
    {
        return $this->incidents
            ->filter(fn ($inc) => $inc->agent)
            ->groupBy('agent_id')
            ->map(fn ($group) => $group->first()->agent->name)
            ->values()
            ->toArray();
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.ip-timeline.show')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
