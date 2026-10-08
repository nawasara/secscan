<?php

namespace Nawasara\Secscan\Livewire\Findings\Section;

use Illuminate\Database\Eloquent\Builder;
use Livewire\Attributes\Computed;
use Livewire\Attributes\On;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Services\FindingTriage;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

class Table extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;

    /** Cap export to protect memory on large finding tables. */
    protected int $exportLimit = 10000;

    /** What opening the page shows: what still needs someone's attention. */
    public const DEFAULT_STATUSES = [SecscanFinding::STATUS_OPEN, SecscanFinding::STATUS_ACKNOWLEDGED];

    #[Url]
    public string $search = '';

    /** @var array<int,string> */
    #[Url]
    public array $severityFilter = [];

    /**
     * Defaults to Terbuka + Diakui, not everything.
     *
     * Opening the page on every finding ever made put Selesai rows on top
     * (sorted by severity and score), so the ones still needing work had to
     * be filtered for by hand each time. Diakui is included: it means
     * "someone is on it", not "done", and hiding it would let a stalled one
     * go unnoticed. The filter chip shows the default, so it is never a
     * silent restriction.
     *
     * @var array<int,string>
     */
    #[Url]
    public array $statusFilter = self::DEFAULT_STATUSES;

    /** @var array<int,string> */
    #[Url]
    public array $threatFilter = [];

    /** @var array<int,string> */
    #[Url]
    public array $sourceFilter = [];

    public int $perPage = 25;

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
        if (in_array(explode('.', $property)[0], ['search', 'severityFilter', 'statusFilter', 'threatFilter', 'sourceFilter'], true)) {
            $this->resetPage();
        }
    }

    /** Detail lives in its own component; it opens the modal itself. */
    public function openDetail(int $id): void
    {
        $this->dispatch('secscan-finding-open', id: $id);
    }

    public function acknowledge(int $id): void
    {
        $this->triage($id, SecscanFinding::STATUS_ACKNOWLEDGED, 'Diakui, sedang ditangani.');
    }

    public function resolve(int $id): void
    {
        $this->triage($id, SecscanFinding::STATUS_RESOLVED, 'Ditandai selesai.');
    }

    public function markFalsePositive(int $id): void
    {
        $this->triage($id, SecscanFinding::STATUS_FALSE_POSITIVE, 'Ditandai false positive.');
    }

    protected function triage(int $id, string $to, string $reason): void
    {
        $this->authorize('secscan.finding.triage');

        app(FindingTriage::class)->transition(SecscanFinding::findOrFail($id), $to, $reason, auth()->id());

        $this->dispatch('toast', ['type' => 'success', 'message' => 'Status temuan diperbarui.']);
    }

    /** The detail modal changed a status; the computed rows re-run on render. */
    #[On('secscan-finding-updated')]
    public function refreshRows(): void
    {
        unset($this->rows);
    }

    /** True when the page shows exactly what it opens on, nothing narrowed. */
    #[Computed]
    public function isDefaultView(): bool
    {
        $status = $this->statusFilter;
        sort($status);
        $default = self::DEFAULT_STATUSES;
        sort($default);

        return $this->search === ''
            && $this->severityFilter === [] && $this->threatFilter === [] && $this->sourceFilter === []
            && $status === $default;
    }

    /** @return array<string,string> */
    #[Computed]
    public function threatOptions(): array
    {
        return SecscanFinding::threatLabels();
    }

    /** One query for the table AND the export, so the file matches the screen. */
    protected function filteredQuery(): Builder
    {
        $term = '%'.addcslashes($this->search, '\\%_').'%';

        return SecscanFinding::query()
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'last_detected_at'))
            ->when($this->search !== '', function ($q) use ($term) {
                $q->where(function ($sub) use ($term) {
                    $sub->where('db_name', 'like', $term)
                        ->orWhere('site_name', 'like', $term)
                        ->orWhere('site_url', 'like', $term);
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
            ->orderByDesc('last_detected_at');
    }

    #[Computed]
    public function rows()
    {
        return $this->filteredQuery()->paginate($this->perPage);
    }

    protected function exportFilename(): string
    {
        return 'secscan-findings';
    }

    /**
     * The current filtered result, not the whole table. The recap anyone
     * asks for is "open judol findings", and exporting everything to filter
     * again in Excel is the work this page already did.
     */
    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return $this->filteredQuery()
            ->limit($this->exportLimit)
            ->get()
            ->map(fn (SecscanFinding $f) => [
                'Situs / DB' => $f->site_name ?: $f->db_name,
                'URL' => $f->site_url ?: $f->scan_url,
                'Sumber' => $f->sourceLabel(),
                'Jenis Ancaman' => $f->threatLabel(),
                'Severity' => $f->severity,
                'Status' => $f->statusLabel(),
                'Score' => $f->score,
                'Bukti' => is_array($f->evidence) ? json_encode($f->evidence, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) : (string) $f->evidence,
                'Pertama' => $f->first_detected_at?->format('Y-m-d H:i:s'),
                'Terakhir' => $f->last_detected_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.findings.section.table');
    }
}
