<?php

namespace Nawasara\Secscan\Livewire\Incidents\Section;

use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\SecurityIncident;

class Table extends Component
{
    use WithPagination;

    #[Url]
    public string $search = '';

    #[Url]
    public string $filterSeverity = '';

    #[Url]
    public string $filterType = '';

    public function updatedSearch(): void { $this->resetPage(); }
    public function updatedFilterSeverity(): void { $this->resetPage(); }
    public function updatedFilterType(): void { $this->resetPage(); }

    public function render()
    {
        $query = SecurityIncident::with('agent')
            ->when($this->search, fn ($q) => $q->where('source_ip', 'like', "%{$this->search}%"))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->when($this->filterType, fn ($q) => $q->where('type', $this->filterType))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('detected_at');

        $incidents = $query->paginate(25);

        $typeOptions = SecurityIncident::query()
            ->selectRaw('type, COUNT(*) as cnt')
            ->groupBy('type')
            ->orderByDesc('cnt')
            ->limit(20)
            ->pluck('cnt', 'type')
            ->keys()
            ->mapWithKeys(fn ($t) => [$t => ucwords(str_replace('_', ' ', $t))])
            ->toArray();

        return view('nawasara-secscan::livewire.pages.incidents.section.table', [
            'incidents'   => $incidents,
            'typeOptions' => $typeOptions,
        ]);
    }
}
