<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\On;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Ui\Livewire\Concerns\HasExport;

class Table extends Component
{
    use HasExport;
    use WithPagination;

    public string $search = '';
    public string $filterStatus = '';

    #[On('agent-registered')]
    public function refresh(): void
    {
        $this->resetPage();
    }

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function updatedFilterStatus(): void
    {
        $this->resetPage();
    }

    protected function exportFilename(): string
    {
        return 'secscan-agents';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        // api_key_hash deliberately excluded — never export credentials.
        return Agent::withCount('incidents')
            ->orderByDesc('last_seen_at')
            ->get()
            ->map(fn (Agent $a) => [
                'Agent ID'    => $a->agent_id,
                'Nama'        => $a->name,
                'Hostname'    => $a->hostname,
                'OS'          => $a->os,
                'Arch'        => $a->arch,
                'Versi'       => $a->agent_version,
                'Web Server'  => $a->web_server,
                'IP Lokal'    => $a->ip_local,
                'Status'      => $a->statusLabel(),
                'Health'      => $a->health_score,
                'Plugins'     => is_array($a->plugins_active) ? implode(', ', $a->plugins_active) : (string) $a->plugins_active,
                'Insiden'     => $a->incidents_count,
                'Terakhir'    => $a->last_seen_at?->format('Y-m-d H:i:s'),
                'Terdaftar'   => $a->registered_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        $query = Agent::query()
            ->withCount('incidents')
            ->when($this->search, fn ($q) => $q->where(function ($q) {
                $q->where('name', 'like', "%{$this->search}%")
                  ->orWhere('hostname', 'like', "%{$this->search}%")
                  ->orWhere('ip_local', 'like', "%{$this->search}%");
            }))
            ->when($this->filterStatus, fn ($q) => $q->where('status', $this->filterStatus))
            ->orderBy('last_seen_at', 'desc')
            ->orderBy('created_at', 'desc');

        $agents = $query->paginate(20);

        return view('nawasara-secscan::livewire.pages.agents.section.table', [
            'agents' => $agents,
        ]);
    }
}
