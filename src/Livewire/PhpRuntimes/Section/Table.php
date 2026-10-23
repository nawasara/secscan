<?php

namespace Nawasara\Secscan\Livewire\PhpRuntimes\Section;

use Illuminate\Database\Eloquent\Builder;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Jobs\ScanPhpRuntimesJob;
use Nawasara\Secscan\Models\PhpRuntime;
use Nawasara\Secscan\Support\PhpPatchLevels;
use Nawasara\Ui\Livewire\Concerns\HasExport;

/**
 * Inventaris versi PHP di ekosistem. Dibuka pada yang perlu ditindak
 * (rentan dan tidak didukung); yang aman bisa dilihat lewat saringan.
 */
class Table extends Component
{
    use HasExport;
    use WithPagination;
    use WithSudo;

    #[Url]
    public string $search = '';

    /** @var array<int,string> */
    #[Url]
    public array $filterStatus = [PhpPatchLevels::VULNERABLE, PhpPatchLevels::EOL];

    #[Url]
    public string $filterSource = '';

    public function mount(): void
    {
        $this->authorize('secscan.view');
    }

    public function updated($property): void
    {
        if (in_array(explode('.', $property)[0], ['search', 'filterStatus', 'filterSource'], true)) {
            $this->resetPage();
        }
    }

    public function scanNow(): void
    {
        $this->authorize('secscan.scan.execute');

        ScanPhpRuntimesJob::dispatch(triggerSource: 'manual');

        $this->dispatch('toast', type: 'info',
            message: 'Pemindaian versi PHP berjalan di latar belakang, biasanya beberapa menit. Muat ulang halaman ini sesudahnya.');
    }

    /**
     * Baris yang keliru atau sudah tidak relevan (situs dipindah, server
     * dimatikan). Pemindaian berikutnya menambahkannya lagi bila masih ada.
     */
    #[RequiresSudo(reason: 'menghapus baris inventaris versi PHP')]
    public function deleteRuntime(int $id): void
    {
        $this->authorize('secscan.finding.triage');

        $row = PhpRuntime::findOrFail($id);
        $row->delete();

        unset($this->rows, $this->stats);
        $this->dispatch('toast', type: 'success', message: 'Baris '.$row->target.' dihapus.');
    }

    /** @return array<string,int> */
    #[Computed]
    public function stats(): array
    {
        $counts = PhpRuntime::query()->selectRaw('status, count(*) as n')->groupBy('status')->pluck('n', 'status');

        return [
            PhpPatchLevels::VULNERABLE => (int) ($counts[PhpPatchLevels::VULNERABLE] ?? 0),
            PhpPatchLevels::EOL => (int) ($counts[PhpPatchLevels::EOL] ?? 0),
            PhpPatchLevels::HIDDEN => (int) ($counts[PhpPatchLevels::HIDDEN] ?? 0),
            PhpPatchLevels::SAFE => (int) ($counts[PhpPatchLevels::SAFE] ?? 0),
            'exposes' => PhpRuntime::where('exposes_version', true)->count(),
        ];
    }

    #[Computed]
    public function hasNarrowing(): bool
    {
        return $this->search !== '' || $this->filterSource !== '';
    }

    #[Computed]
    public function lastScan(): ?string
    {
        return PhpRuntime::max('last_seen_at');
    }

    protected function filteredQuery(): Builder
    {
        $term = '%'.addcslashes($this->search, '\\%_').'%';

        return PhpRuntime::query()
            ->when($this->search !== '', fn ($q) => $q->where(fn ($w) => $w
                ->where('target', 'like', $term)
                ->orWhere('origin', 'like', $term)
                ->orWhere('php_version', 'like', $term)))
            ->when($this->filterStatus !== [], fn ($q) => $q->whereIn('status', $this->filterStatus))
            ->when($this->filterSource !== '', fn ($q) => $q->where('source', $this->filterSource))
            ->orderByRaw("CASE status WHEN 'vulnerable' THEN 0 WHEN 'eol' THEN 1 WHEN 'hidden' THEN 2 ELSE 3 END")
            ->orderBy('target');
    }

    #[Computed]
    public function rows()
    {
        return $this->filteredQuery()->paginate(25);
    }

    protected function exportFilename(): string
    {
        return 'secscan-versi-php';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        $levels = PhpPatchLevels::fromConfig();

        return $this->filteredQuery()->limit(10000)->get()->map(fn (PhpRuntime $r) => [
            'Sasaran' => $r->target,
            'Sumber' => PhpRuntime::sourceLabel($r->source),
            'Asal' => $r->origin,
            'Handler' => $r->handler,
            'Versi PHP' => $r->php_version,
            'Status' => PhpPatchLevels::label($r->status),
            'Versi tujuan' => $levels->targetFor($r->php_version),
            'Memamerkan versi' => $r->exposes_version ? 'Ya' : 'Tidak',
            'Terakhir terlihat' => $r->last_seen_at?->format('Y-m-d H:i'),
        ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.php-runtimes.section.table', [
            'levels' => PhpPatchLevels::fromConfig(),
        ]);
    }
}
