<?php

namespace Nawasara\Secscan\Livewire\IpBlocks\Section;

use Illuminate\Database\Eloquent\Builder;
use Livewire\Attributes\Computed;
use Livewire\Attributes\On;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Jobs\UnblockIpsJob;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Services\IpBlockManager;
use Nawasara\Ui\Livewire\Concerns\HasExport;
use Nawasara\Ui\Livewire\Concerns\HasTimeWindow;

/**
 * The audit and control surface for blocks: who is blocked, why, since when,
 * and the way out.
 *
 * Blocks never expire, by decision (8 October 2026). That makes this page
 * the only cleanup path, so it can narrow down to "4xx storms older than 30
 * days" and lift the whole result at once.
 */
class Table extends Component
{
    use HasExport;
    use HasTimeWindow;
    use WithPagination;
    use WithSudo;

    #[Url]
    public string $search = '';

    /** Opens on active blocks: lifted ones are history, not something to act on. */
    #[Url]
    public string $filterStatus = IpBlock::STATUS_ACTIVE;

    /** @var array<int,string> */
    #[Url]
    public array $filterReason = [];

    #[Url]
    public string $filterSource = '';

    public function mount(): void
    {
        $this->authorize('secscan.ip-block.manage');
    }

    /** Blocks are permanent, so the whole history is the useful default. */
    protected function defaultTimeWindow(): string
    {
        return 'all';
    }

    public function updated($property): void
    {
        if (in_array(explode('.', $property)[0], ['search', 'filterStatus', 'filterReason', 'filterSource'], true)) {
            $this->resetPage();
        }
    }

    #[On('ip-block-saved')]
    public function refreshRows(): void
    {
        unset($this->rows, $this->stats);
    }

    #[RequiresSudo(reason: 'membuka blokir IP (mengembalikan akses)')]
    public function unblock(int $id): void
    {
        $this->authorize('secscan.ip-block.manage');

        $block = IpBlock::findOrFail($id);

        if (! app(IpBlockManager::class)->unblock($block, auth()->id())) {
            $this->dispatch('toast', type: 'error', message: 'Cloudflare menolak menghapus aturannya. IP '.$block->ip.' MASIH terblokir.');

            return;
        }

        $this->refreshRows();
        $this->dispatch('toast', type: 'success', message: 'Blokir IP '.$block->ip.' dicabut.');
    }

    /**
     * Lift every ACTIVE block in the current filtered result.
     *
     * Queued in chunks: each block is one Cloudflare call, and hundreds of
     * them inside this request would time out half-way.
     */
    #[RequiresSudo(reason: 'mencabut banyak blokir IP sekaligus')]
    public function unblockFiltered(): void
    {
        $this->authorize('secscan.ip-block.manage');

        $ids = $this->filteredQuery()
            ->where('status', IpBlock::STATUS_ACTIVE)
            ->pluck('id');

        if ($ids->isEmpty()) {
            return;
        }

        foreach ($ids->chunk(UnblockIpsJob::CHUNK) as $chunk) {
            UnblockIpsJob::dispatch($chunk->values()->all(), auth()->id());
        }

        $this->dispatch('toast', type: 'info',
            message: $ids->count().' blokir sedang dicabut di latar belakang. Muat ulang halaman ini beberapa menit lagi.');
    }

    #[Computed]
    public function activeInFilter(): int
    {
        return $this->filteredQuery()->where('status', IpBlock::STATUS_ACTIVE)->count();
    }

    #[Computed]
    public function hasNarrowing(): bool
    {
        return $this->search !== '' || $this->filterReason !== [] || $this->filterSource !== ''
            || $this->window !== 'all';
    }

    /** @return array<string,string> */
    #[Computed]
    public function reasonOptions(): array
    {
        return IpBlock::query()->distinct()->orderBy('reason')->pluck('reason')
            ->filter()
            ->mapWithKeys(fn ($r) => [$r => IpBlock::reasonLabel($r)])
            ->all();
    }

    /** @return array<string,int> */
    #[Computed]
    public function stats(): array
    {
        return [
            'active' => IpBlock::where('status', IpBlock::STATUS_ACTIVE)->count(),
            'old' => IpBlock::where('status', IpBlock::STATUS_ACTIVE)->where('blocked_at', '<', now()->subDays(30))->count(),
            'dry_run' => IpBlock::where('dry_run', true)->where('status', IpBlock::STATUS_ACTIVE)->count(),
            'removed' => IpBlock::where('status', IpBlock::STATUS_REMOVED)->count(),
        ];
    }

    /** One query for the table, the export and the bulk action. */
    protected function filteredQuery(): Builder
    {
        $term = '%'.addcslashes($this->search, '\\%_').'%';

        return IpBlock::query()
            ->tap(fn ($q) => $this->applyTimeWindow($q, 'blocked_at'))
            ->when($this->search !== '', fn ($q) => $q->where('ip', 'like', $term))
            ->when($this->filterStatus !== '', fn ($q) => $q->where('status', $this->filterStatus))
            ->when($this->filterReason !== [], fn ($q) => $q->whereIn('reason', $this->filterReason))
            ->when($this->filterSource === 'auto', fn ($q) => $q->whereNull('blocked_by'))
            ->when($this->filterSource === 'manual', fn ($q) => $q->whereNotNull('blocked_by'))
            ->orderByDesc('blocked_at');
    }

    #[Computed]
    public function rows()
    {
        return $this->filteredQuery()->with('incident')->paginate(25);
    }

    protected function exportFilename(): string
    {
        return 'secscan-blokir-ip';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return $this->filteredQuery()
            ->limit(10000)
            ->get()
            ->map(fn (IpBlock $b) => [
                'IP' => $b->ip,
                'Status' => $b->isActive() ? 'Aktif' : 'Dicabut',
                'Mode' => $b->dry_run ? 'Uji (dry-run)' : 'Diterapkan',
                'Alasan' => IpBlock::reasonLabel($b->reason),
                'Sumber' => $b->blocked_by ? 'Manual' : 'Otomatis',
                'CF Rule ID' => $b->cf_rule_id,
                'Diblokir' => $b->blocked_at?->format('Y-m-d H:i:s'),
                'Dicabut' => $b->unblocked_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.ip-blocks.section.table');
    }
}
