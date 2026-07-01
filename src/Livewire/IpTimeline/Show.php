<?php

namespace Nawasara\Secscan\Livewire\IpTimeline;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Nawasara\Secscan\Models\SecurityIncident;

class Show extends Component
{
    public string $ip = '';

    public function mount(string $ip): void
    {
        $this->ip = $ip;
        $this->authorize('secscan.view');
    }

    #[Computed]
    public function incidents()
    {
        return SecurityIncident::with('agent')
            ->where('source_ip', $this->ip)
            ->orderByDesc('detected_at')
            ->get();
    }

    #[Computed]
    public function summary(): array
    {
        $incs = $this->incidents;

        return [
            'total'      => $incs->count(),
            'critical'   => $incs->where('severity', SecurityIncident::SEVERITY_CRITICAL)->count(),
            'high'       => $incs->where('severity', SecurityIncident::SEVERITY_HIGH)->count(),
            'agents'     => $incs->pluck('agent_id')->unique()->count(),
            'first_seen' => $incs->min('detected_at'),
            'last_seen'  => $incs->max('detected_at'),
            'correlated' => $incs->where('correlated', true)->count(),
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
