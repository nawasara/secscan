<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Illuminate\Database\Eloquent\Builder;
use Livewire\Attributes\On;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentCommand;
use Nawasara\Ui\Livewire\Concerns\HasExport;

class Table extends Component
{
    use HasExport;
    use WithPagination;
    use WithSudo;

    #[Url]
    public string $search = '';

    #[Url]
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

    /**
     * Retire an agent whose server is gone or replaced. See Agent::revoke().
     *
     * Sudo: it cuts off a server's security monitoring, and someone choosing
     * the wrong row should have to confirm who they are first.
     */
    #[RequiresSudo(reason: 'mencabut agen keamanan dari sebuah server')]
    public function revoke(int $id): void
    {
        $this->authorize('secscan.agent.delete');

        $agent = Agent::findOrFail($id);
        $cancelled = $agent->revoke(auth()->id());

        $this->dispatch('agent-registered');
        $this->dispatch('toast', type: 'success', message: 'Agen '.$agent->name.' dicabut'
            .($cancelled > 0 ? ", {$cancelled} perintah tertahan dibatalkan." : '.'));
    }

    protected function filteredQuery(): Builder
    {
        $term = '%'.addcslashes($this->search, '\\%_').'%';

        return Agent::query()
            ->withCount('incidents')
            ->withCount(['commands as stuck_commands_count' => fn ($q) => $q
                ->where('status', AgentCommand::STATUS_APPROVED)->whereNull('sent_at')])
            ->when($this->search !== '', fn ($q) => $q->where(function ($q) use ($term) {
                $q->where('name', 'like', $term)
                    ->orWhere('hostname', 'like', $term)
                    ->orWhere('ip_local', 'like', $term);
            }))
            ->when($this->filterStatus === 'online', fn ($q) => $q->online())
            ->when($this->filterStatus === 'offline', fn ($q) => $q->offline())
            ->when($this->filterStatus === Agent::STATUS_NEVER, fn ($q) => $q->where('status', Agent::STATUS_NEVER))
            ->orderBy('last_seen_at', 'desc')
            ->orderBy('created_at', 'desc');
    }

    protected function exportFilename(): string
    {
        return 'secscan-agen';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        // api_key_hash deliberately excluded — never export credentials.
        return $this->filteredQuery()
            ->get()
            ->map(fn (Agent $a) => [
                'Agent ID' => $a->agent_id,
                'Nama' => $a->name,
                'Hostname' => $a->hostname,
                'OS' => $a->os,
                'Arch' => $a->arch,
                'Versi' => $a->versionLabel(),
                'Web Server' => $a->web_server,
                'IP Lokal' => $a->ip_local,
                'Status' => $a->statusLabel(),
                'Health' => $a->health_score,
                'Plugins' => is_array($a->plugins_active) ? implode(', ', $a->plugins_active) : (string) $a->plugins_active,
                'Insiden' => $a->incidents_count,
                'Perintah tertahan' => $a->stuck_commands_count,
                'Terakhir' => $a->last_seen_at?->format('Y-m-d H:i:s'),
                'Terdaftar' => $a->registered_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.table', [
            'agents' => $this->filteredQuery()->paginate(20),
        ]);
    }
}
