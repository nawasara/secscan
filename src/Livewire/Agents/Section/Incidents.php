<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\SecurityIncident;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

/**
 * Security incidents for a single agent. Extracted from Agents\Show so the
 * detail page can tab between findings / incidents / commands and so incidents
 * get their own export button.
 */
class Incidents extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;

    public int $agentDbId;
    public string $filterSeverity = '';

    protected int $exportLimit = 10000;

    public function mount(int $agentDbId): void
    {
        $this->agentDbId = $agentDbId;
    }

    /** Per-agent incidents span a long history; default to 30 days. */
    protected function defaultTimeWindow(): string
    {
        return '30d';
    }

    public function updatedFilterSeverity(): void
    {
        $this->resetPage();
    }

    protected function baseQuery()
    {
        return SecurityIncident::where('agent_id', $this->agentDbId);
    }

    public function incidents()
    {
        return $this->baseQuery()
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'last_seen_at'))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('last_seen_at')
            ->paginate(20);
    }

    protected function exportFilename(): string
    {
        return 'secscan-incidents-agent-'.$this->agentDbId;
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return $this->baseQuery()
            ->orderByDesc('last_seen_at')
            ->limit($this->exportLimit)
            ->get()
            ->map(fn (SecurityIncident $inc) => [
                'Incident ID' => $inc->incident_id,
                'Tipe'        => $inc->typeLabel(),
                'Severity'    => $inc->severity,
                'Source IP'   => $inc->source_ip,
                'Score'       => $inc->score,
                'Kejadian'    => $inc->occurrences,
                'MITRE'       => $inc->mitre_technique,
                'MITRE Nama'  => $inc->mitreName(),
                'Evidence'    => collect($inc->evidence ?? [])->pluck('raw')->implode(' | '),
                'Terdeteksi'  => $inc->detected_at?->format('Y-m-d H:i:s'),
                'Terakhir'    => $inc->last_seen_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.incidents', [
            'incidents' => $this->incidents(),
        ]);
    }
}
