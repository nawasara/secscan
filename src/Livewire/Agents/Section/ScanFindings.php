<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\On;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\AgentScanFinding;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class ScanFindings extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;

    public int $agentDbId;       // nawasara_agents.id (not the agent_id string)
    public string $filterStatus   = 'open';
    public string $filterSeverity = '';
    public string $filterCategory = '';

    public ?int   $triageId   = null;
    public string $triageNote = '';
    public string $triageAction = ''; // 'acknowledge' | 'resolve' | 'false_positive'

    public function mount(int $agentDbId): void
    {
        $this->agentDbId = $agentDbId;
    }

    /** Scan findings accumulate; default to a 30-day window. */
    protected function defaultTimeWindow(): string
    {
        return '30d';
    }

    public function findings()
    {
        return AgentScanFinding::where('agent_id', $this->agentDbId)
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'detected_at'))
            ->when($this->filterStatus,   fn ($q) => $q->where('status', $this->filterStatus))
            ->when($this->filterSeverity, fn ($q) => $q->where('severity', $this->filterSeverity))
            ->when($this->filterCategory, fn ($q) => $q->where('category', $this->filterCategory))
            ->orderByRaw("FIELD(severity, 'critical','high','medium')")
            ->orderByDesc('detected_at')
            ->paginate(15);
    }

    public function stats(): array
    {
        $base = AgentScanFinding::where('agent_id', $this->agentDbId);

        return [
            'total'     => (clone $base)->count(),
            'open'      => (clone $base)->where('status', AgentScanFinding::STATUS_OPEN)->count(),
            'critical'  => (clone $base)->where('severity', 'critical')->where('status', AgentScanFinding::STATUS_OPEN)->count(),
            'webshells' => (clone $base)->where('category', 'webshell')->where('status', '!=', AgentScanFinding::STATUS_FALSE_POSITIVE)->count(),
        ];
    }

    public function openTriage(int $id, string $action): void
    {
        $this->authorize('secscan.agent.scan');
        $this->triageId     = $id;
        $this->triageAction = $action;
        $this->triageNote   = '';
        $this->dispatch('modal-open:scan-triage-' . $this->agentDbId);
    }

    public function confirmTriage(): void
    {
        $this->authorize('secscan.agent.scan');

        $finding = AgentScanFinding::where('id', $this->triageId)
            ->where('agent_id', $this->agentDbId)
            ->firstOrFail();

        $newStatus = match ($this->triageAction) {
            'acknowledge'    => AgentScanFinding::STATUS_ACKNOWLEDGED,
            'resolve'        => AgentScanFinding::STATUS_RESOLVED,
            'false_positive' => AgentScanFinding::STATUS_FALSE_POSITIVE,
            default          => $finding->status,
        };

        $finding->update([
            'status'      => $newStatus,
            'triaged_by'  => auth()->id(),
            'triaged_at'  => now(),
            'triage_note' => $this->triageNote ?: null,
        ]);

        $this->triageId = null;
        $this->dispatch('close-modal', 'scan-triage-' . $this->agentDbId);
        $this->dispatch('toast', type: 'success', message: 'Finding updated.');
    }

    #[On('scan-finding-triaged')]
    public function refresh(): void
    {
        $this->resetPage();
    }

    public function updatedFilterStatus(): void   { $this->resetPage(); }
    public function updatedFilterSeverity(): void { $this->resetPage(); }
    public function updatedFilterCategory(): void { $this->resetPage(); }

    protected function exportFilename(): string
    {
        return 'secscan-scan-findings-agent-'.$this->agentDbId;
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return AgentScanFinding::where('agent_id', $this->agentDbId)
            ->orderByRaw("FIELD(severity, 'critical','high','medium')")
            ->orderByDesc('detected_at')
            ->get()
            ->map(fn (AgentScanFinding $f) => [
                'Finding ID'  => $f->finding_id,
                'Path'        => $f->path,
                'Signature'   => $f->sig_name,
                'Signature ID' => $f->signature_id,
                'Kategori'    => $f->categoryLabel(),
                'Severity'    => $f->severity,
                'Score'       => $f->score,
                'MITRE'       => $f->mitre_technique,
                'MITRE Nama'  => $f->mitreName(),
                'Status'      => $f->status,
                'Baris Cocok' => $f->matched_line,
                'Deskripsi'   => $f->description,
                'Terdeteksi'  => $f->detected_at?->format('Y-m-d H:i:s'),
                'Terakhir'    => $f->last_seen_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.scan-findings', [
            'findings' => $this->findings(),
            'stats'    => $this->stats(),
        ]);
    }
}
