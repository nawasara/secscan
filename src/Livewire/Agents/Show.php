<?php

namespace Nawasara\Secscan\Livewire\Agents;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Show extends Component
{
    use HasTimeWindow;
    use WithPagination;

    public string $agentId = '';
    public string $filterSeverity = '';

    public function mount(string $agentId): void
    {
        $this->agentId = $agentId;
        $this->authorize('secscan.agent.view');
    }

    /** Per-agent incidents span a long history; default to 30 days. */
    protected function defaultTimeWindow(): string
    {
        return '30d';
    }

    #[Computed]
    public function agent(): ?Agent
    {
        return Agent::where('agent_id', $this->agentId)->firstOrFail();
    }

    #[Computed]
    public function recentHeartbeats()
    {
        return $this->agent->heartbeats()
            ->latest()
            ->limit(20)
            ->get();
    }

    #[Computed]
    public function incidentStats(): array
    {
        $base = $this->agent->incidents();

        return [
            'total'    => (clone $base)->count(),
            'critical' => (clone $base)->where('severity', SecurityIncident::SEVERITY_CRITICAL)->count(),
            'high'     => (clone $base)->where('severity', SecurityIncident::SEVERITY_HIGH)->count(),
            'today'    => (clone $base)->whereDate('detected_at', today())->count(),
        ];
    }

    #[Computed]
    public function incidents()
    {
        return $this->agent->incidents()
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'detected_at'))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('detected_at')
            ->paginate(20);
    }

    public function updatedFilterSeverity(): void
    {
        $this->resetPage();
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.show')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
