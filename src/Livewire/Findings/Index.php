<?php

namespace Nawasara\Secscan\Livewire\Findings;

use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Secscan\Models\SecurityIncident;

class Index extends Component
{
    use WithPagination;

    #[Url]
    public string $tab = 'findings'; // findings|incidents

    #[Url]
    public string $search = '';

    // Incidents tab filters
    #[Url]
    public string $incSearch = '';

    #[Url]
    public string $incSeverity = '';

    #[Url]
    public string $incType = '';

    /** @var array<int,string> */
    #[Url]
    public array $severityFilter = [];

    /** @var array<int,string> */
    #[Url]
    public array $statusFilter = [];

    /** @var array<int,string> */
    #[Url]
    public array $threatFilter = [];

    /** @var array<int,string> */
    #[Url]
    public array $sourceFilter = [];

    public int $perPage = 25;

    /** Finding currently open in the detail/triage modal. */
    public ?int $detailId = null;

    /** Incident currently open in the incident evidence modal (Incidents Agent tab). */
    public ?int $incidentDetailId = null;

    public string $triageReason = '';

    public function updatedTab(): void
    {
        $this->resetPage();
    }

    public function updated($property): void
    {
        if (in_array($property, ['search', 'severityFilter', 'statusFilter', 'threatFilter', 'sourceFilter', 'incSearch', 'incSeverity', 'incType'], true)) {
            $this->resetPage();
        }
    }

    public function openDetail(int $id): void
    {
        $this->detailId = $id;
        $this->triageReason = '';
        $this->dispatch('modal-open:secscan-finding-detail');
    }

    public function openIncidentDetail(int $id): void
    {
        $this->incidentDetailId = $id;
        $this->dispatch('modal-open:secscan-incident-detail');
    }

    #[Computed]
    public function incidentDetail(): ?SecurityIncident
    {
        return $this->incidentDetailId
            ? SecurityIncident::with('agent')->find($this->incidentDetailId)
            : null;
    }

    public function acknowledge(int $id): void
    {
        $this->transition($id, SecscanFinding::STATUS_ACKNOWLEDGED, 'Diakui — sedang ditangani.');
    }

    public function markFalsePositive(int $id): void
    {
        $this->transition($id, SecscanFinding::STATUS_FALSE_POSITIVE, $this->triageReason ?: 'Ditandai false positive.');
    }

    public function resolve(int $id): void
    {
        $this->transition($id, SecscanFinding::STATUS_RESOLVED, $this->triageReason ?: 'Ditandai selesai.');
    }

    /**
     * Apply a triage status change: gate, record history, resolve the alert if
     * the finding is being dismissed.
     */
    protected function transition(int $id, string $to, string $reason): void
    {
        $this->authorize('secscan.finding.triage');

        $finding = SecscanFinding::findOrFail($id);
        $from = $finding->status;

        if ($from === $to) {
            return;
        }

        $finding->status = $to;
        if ($to === SecscanFinding::STATUS_ACKNOWLEDGED) {
            $finding->acknowledged_by = auth()->id();
            $finding->acknowledged_at = now();
            $finding->acknowledged_reason = $reason;
        }
        if (in_array($to, [SecscanFinding::STATUS_RESOLVED, SecscanFinding::STATUS_FALSE_POSITIVE], true)) {
            $finding->resolved_by = auth()->id();
            $finding->resolved_at = now();
            $finding->resolved_reason = $reason;
        }
        $finding->save();

        SecscanFindingHistory::create([
            'finding_id' => $finding->id,
            'status_from' => $from,
            'status_to' => $to,
            'changed_by' => auth()->id(),
            'reason' => $reason,
            'created_at' => now(),
        ]);

        // Dismissing a finding clears its alert so notifications stop.
        if (in_array($to, [SecscanFinding::STATUS_RESOLVED, SecscanFinding::STATUS_FALSE_POSITIVE], true)) {
            Alerter::resolve('secscan.site.compromised', 'SecscanFinding', (string) $finding->id);
            Alerter::resolve('secscan.site.suspicious', 'SecscanFinding', (string) $finding->id);
        }

        $this->triageReason = '';
        $this->dispatch('close-modal', 'secscan-finding-detail');
        $this->dispatch('toast', ['type' => 'success', 'message' => 'Status temuan diperbarui.']);
    }

    #[Computed]
    public function detail(): ?SecscanFinding
    {
        return $this->detailId ? SecscanFinding::with('histories')->find($this->detailId) : null;
    }

    /** @return array<string,string> */
    #[Computed]
    public function threatOptions(): array
    {
        return SecscanFinding::threatLabels();
    }

    #[Computed]
    public function incidents()
    {
        return SecurityIncident::with('agent')
            ->when($this->incSearch, fn ($q) => $q->where('source_ip', 'like', "%{$this->incSearch}%"))
            ->when($this->incSeverity, fn ($q) => $q->where('severity', $this->incSeverity))
            ->when($this->incType, fn ($q) => $q->where('type', $this->incType))
            ->orderByRaw("FIELD(severity, 'critical','high','medium','info')")
            ->orderByDesc('detected_at')
            ->paginate($this->perPage);
    }

    #[Computed]
    public function incidentTypeOptions(): array
    {
        return SecurityIncident::query()
            ->selectRaw('type, COUNT(*) as cnt')
            ->groupBy('type')
            ->orderByDesc('cnt')
            ->limit(20)
            ->pluck('cnt', 'type')
            ->keys()
            ->mapWithKeys(fn ($t) => [$t => ucwords(str_replace('_', ' ', $t))])
            ->toArray();
    }

    #[Computed]
    public function rows()
    {
        return SecscanFinding::query()
            ->when($this->search !== '', function ($q) {
                $q->where(function ($sub) {
                    $sub->where('db_name', 'like', "%{$this->search}%")
                        ->orWhere('site_name', 'like', "%{$this->search}%")
                        ->orWhere('site_url', 'like', "%{$this->search}%");
                });
            })
            ->when(! empty($this->severityFilter), fn ($q) => $q->whereIn('severity', $this->severityFilter))
            ->when(! empty($this->statusFilter), fn ($q) => $q->whereIn('status', $this->statusFilter))
            ->when(! empty($this->threatFilter), fn ($q) => $q->whereIn('threat_type', $this->threatFilter))
            ->when(! empty($this->sourceFilter), fn ($q) => $q->where(function ($sub) {
                foreach ($this->sourceFilter as $src) {
                    if ($src === 'sql') {
                        // Legacy rows have null scan_source; treat them as 'sql'
                        $sub->orWhereNull('scan_source')->orWhere('scan_source', 'sql');
                    } else {
                        $sub->orWhere('scan_source', $src);
                    }
                }
            }))
            ->orderByRaw("FIELD(severity, 'critical','warning','info')")
            ->orderByDesc('score')
            ->orderByDesc('last_detected_at')
            ->paginate($this->perPage);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.findings.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
