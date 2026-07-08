<?php

namespace Nawasara\Secscan\Livewire\Agents;

use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentCommand;
use Nawasara\Secscan\Models\AgentScanFinding;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasExport;

class Show extends Component
{
    use HasExport;

    public string $agentId = '';

    /** Active detail tab: findings | incidents | commands. */
    #[Url]
    public string $tab = 'findings';

    public function mount(string $agentId): void
    {
        $this->agentId = $agentId;
        $this->authorize('secscan.agent.view');
    }

    public function setTab(string $tab): void
    {
        if (in_array($tab, ['findings', 'incidents', 'commands'], true)) {
            $this->tab = $tab;
        }
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

    /** Counts shown as badges on the tab switcher. */
    #[Computed]
    public function tabCounts(): array
    {
        return [
            'findings'  => AgentScanFinding::where('agent_id', $this->agent->id)
                ->where('status', AgentScanFinding::STATUS_OPEN)->count(),
            'incidents' => $this->incidentStats['total'],
            'commands'  => AgentCommand::where('agent_id', $this->agent->id)
                ->where('status', AgentCommand::STATUS_PENDING)->count(),
        ];
    }

    protected function exportFilename(): string
    {
        return 'secscan-heartbeats-'.$this->agentId;
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return $this->agent->heartbeats()
            ->latest()
            ->limit(1000)
            ->get()
            ->map(fn ($hb) => [
                'Waktu'        => $hb->created_at?->format('Y-m-d H:i:s'),
                'Versi'        => $hb->agent_version,
                'Health'       => $hb->health_score,
                'CPU %'        => $hb->metrics['cpu_percent'] ?? null,
                'RAM MB'       => $hb->metrics['mem_used_mb'] ?? null,
                'Disk %'       => $hb->metrics['disk_used_percent'] ?? null,
                'Pending'      => $hb->pending_incidents,
                'Plugins'      => is_array($hb->plugins_active) ? implode(', ', $hb->plugins_active) : (string) $hb->plugins_active,
                'Uptime (dtk)' => $hb->uptime_seconds,
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.show')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
