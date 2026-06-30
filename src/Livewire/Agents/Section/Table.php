<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\On;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\Agent;

class Table extends Component
{
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

    public function render()
    {
        $query = Agent::query()
            ->when($this->search, fn ($q) => $q->where(function ($q) {
                $q->where('name', 'like', "%{$this->search}%")
                  ->orWhere('hostname', 'like', "%{$this->search}%")
                  ->orWhere('ip_local', 'like', "%{$this->search}%");
            }))
            ->orderBy('last_seen_at', 'desc')
            ->orderBy('created_at', 'desc');

        $agents = $query->paginate(20);

        return view('nawasara-secscan::livewire.pages.agents.section.table', [
            'agents' => $agents,
        ]);
    }
}
