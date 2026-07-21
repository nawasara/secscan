<?php

namespace Nawasara\Secscan\Livewire\Findings;

use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Alerting\Facades\Alerter;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Models\SecscanFindingHistory;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Index extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;

    /** Cap export to protect memory on large finding tables. */
    protected int $exportLimit = 10000;

    #[Url]
    public string $search = '';

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

    public string $triageReason = '';

    /**
     * Security findings span a long history and users triage by recency,
     * so default to a 30-day window rather than the trait's 7d default.
     */
    protected function defaultTimeWindow(): string
    {
        return '30d';
    }

    public function updated($property): void
    {
        if (in_array($property, ['search', 'severityFilter', 'statusFilter', 'threatFilter', 'sourceFilter'], true)) {
            $this->resetPage();
        }
    }

    public function openDetail(int $id): void
    {
        $this->detailId = $id;
        $this->triageReason = '';
        $this->dispatch('modal-open:secscan-finding-detail');
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
        $this->dispatch('modal-close:secscan-finding-detail');
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
    public function rows()
    {
        return SecscanFinding::query()
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'last_detected_at'))
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

    protected function exportFilename(): string
    {
        return 'secscan-findings';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return SecscanFinding::query()
            ->orderByRaw("FIELD(severity, 'critical','warning','info')")
            ->orderByDesc('last_detected_at')
            ->limit($this->exportLimit)
            ->get()
            ->map(fn (SecscanFinding $f) => [
                'Situs / DB'    => $f->site_name ?: $f->db_name,
                'URL'           => $f->site_url ?: $f->scan_url,
                'Sumber'        => $f->sourceLabel(),
                'Jenis Ancaman' => $f->threatLabel(),
                'Severity'      => $f->severity,
                'Status'        => $f->statusLabel(),
                'Score'         => $f->score,
                'Bukti'         => is_array($f->evidence) ? json_encode($f->evidence, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : (string) $f->evidence,
                'Pertama'       => $f->first_detected_at?->format('Y-m-d H:i:s'),
                'Terakhir'      => $f->last_detected_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.findings.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
