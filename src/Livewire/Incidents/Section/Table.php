<?php

namespace Nawasara\Secscan\Livewire\Incidents\Section;

use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Table extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;

    /** Cap export to protect memory on large incident tables. */
    protected int $exportLimit = 10000;

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

    protected function exportFilename(): string
    {
        return 'secscan-incidents';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        // The current filtered result, not the whole table: 79 thousand rows
        // with every agent's noise is not a report anyone can use.
        return $this->filteredQuery()
            ->limit($this->exportLimit)
            ->get()
            ->map(fn (SecurityIncident $inc) => [
                'Incident ID'   => $inc->incident_id,
                'Agent'         => $inc->agent?->name,
                'Hostname'      => $inc->agent?->hostname,
                'Jenis'         => $inc->typeLabel(),
                'Severity'      => $inc->severityLabel(),
                'Source IP'     => $inc->source_ip,
                'Score'         => $inc->score,
                'Kejadian'      => $inc->occurrences,
                'MITRE'         => $inc->mitre_technique,
                'MITRE Nama'    => $inc->mitreName(),
                'Correlated'    => $inc->correlated ? 'Ya' : 'Tidak',
                'Evidence'      => collect($inc->evidence ?? [])->pluck('raw')->implode(' | '),
                'Terdeteksi'    => $inc->detected_at?->format('Y-m-d H:i:s'),
                'Terakhir'      => $inc->last_seen_at?->format('Y-m-d H:i:s'),
            ]);
    }

    /** True when anything narrows the list beyond the time window. */
    public function hasFilters(): bool
    {
        return $this->search !== '' || $this->filterSeverity !== '' || $this->filterType !== '';
    }

    /**
     * One query for the table and the export.
     *
     * Windowed and ordered by last_seen_at, so an ongoing (aggregated) attack
     * that started weeks ago still surfaces in the recent window.
     */
    protected function filteredQuery()
    {
        $term = '%'.addcslashes($this->search, '\%_').'%';

        return SecurityIncident::with('agent')
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'last_seen_at'))
            ->when($this->search !== '', fn ($q) => $q->where('source_ip', 'like', $term))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->when($this->filterType, fn ($q) => $q->where('type', $this->filterType))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('last_seen_at');
    }

    public function render()
    {
        $incidents = $this->filteredQuery()->paginate(25);

        // Which of the IPs on this page are currently blocked at the edge? The
        // "Diblokir" badge reflects IP state, not whether THIS incident
        // triggered the block. One query for the page's IPs (no N+1).
        $pageIps = collect($incidents->items())
            ->pluck('source_ip')->filter()->unique()->all();
        $blockedIps = $pageIps
            ? IpBlock::where('status', IpBlock::STATUS_ACTIVE)
                ->whereIn('ip', $pageIps)
                ->pluck('ip')
                ->flip()
                ->all()
            : [];

        $typeOptions = SecurityIncident::query()
            ->selectRaw('type, COUNT(*) as cnt')
            ->groupBy('type')
            ->orderByDesc('cnt')
            ->limit(20)
            ->pluck('cnt', 'type')
            ->keys()
            ->mapWithKeys(fn ($t) => [$t => SecurityIncident::labelForType($t)])
            ->toArray();

        return view('nawasara-secscan::livewire.pages.incidents.section.table', [
            'incidents'   => $incidents,
            'typeOptions' => $typeOptions,
            'blockedIps'  => $blockedIps,
        ]);
    }
}
