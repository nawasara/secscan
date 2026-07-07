<?php

namespace Nawasara\Secscan\Livewire\Incidents\Section;

use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Table extends Component
{
    use HasTimeWindow;
    use WithPagination;

    #[Url]
    public string $search = '';

    #[Url]
    public string $filterSeverity = '';

    #[Url]
    public string $filterType = '';

    public ?SecurityIncident $selectedIncident = null;

    /**
     * Incidents accumulate over time; default to a 30-day window so the
     * page isn't dominated by months-old attacker noise on first load.
     */
    protected function defaultTimeWindow(): string
    {
        return '30d';
    }

    public function updatedSearch(): void { $this->resetPage(); }
    public function updatedFilterSeverity(): void { $this->resetPage(); }
    public function updatedFilterType(): void { $this->resetPage(); }

    public function openDetail(int $id): void
    {
        $this->selectedIncident = SecurityIncident::with('agent')->find($id);
        $this->dispatch('modal-open:incident-detail-modal');
    }

    public function render()
    {
        // Window + order by last_seen_at so an ongoing (aggregated) attack that
        // started weeks ago still surfaces in the recent window.
        $query = SecurityIncident::with('agent')
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'last_seen_at'))
            ->when($this->search, fn ($q) => $q->where('source_ip', 'like', "%{$this->search}%"))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->when($this->filterType, fn ($q) => $q->where('type', $this->filterType))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('last_seen_at');

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
