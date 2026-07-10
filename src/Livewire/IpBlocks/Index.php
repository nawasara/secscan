<?php

namespace Nawasara\Secscan\Livewire\IpBlocks;

use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Services\CloudflareBlockService;
use Nawasara\Ui\Livewire\Concerns\HasExport;

/**
 * IP Blocks — the audit + control surface for the Decision Engine's auto-block.
 * Lists every block (active/removed, real/dry-run) and lets an operator unblock
 * an IP manually. Unblocking re-opens access, so it's sudo-gated.
 */
class Index extends Component
{
    use HasExport;
    use WithPagination;
    use WithSudo;

    #[Url]
    public string $search = '';

    #[Url]
    public string $filterStatus = '';

    public function mount(): void
    {
        $this->authorize('secscan.ip-block.manage');
    }

    public function updatedSearch(): void { $this->resetPage(); }
    public function updatedFilterStatus(): void { $this->resetPage(); }

    /**
     * Remove a block: delete the Cloudflare rule (if any) then mark removed.
     * Sudo required — this restores access for the IP.
     */
    #[RequiresSudo(reason: 'membuka blokir IP (mengembalikan akses)')]
    public function unblock(int $id): void
    {
        $this->authorize('secscan.ip-block.manage');

        $block = IpBlock::findOrFail($id);
        if (! $block->isActive()) {
            return;
        }

        // Only touch Cloudflare for a real (non-dry-run) block that has a rule id.
        if (! $block->dry_run && $block->cf_rule_id) {
            app(CloudflareBlockService::class)->unblock($block->cf_rule_id);
        }

        $block->update([
            'status'       => IpBlock::STATUS_REMOVED,
            'unblocked_by' => auth()->id(),
            'unblocked_at' => now(),
        ]);

        // Clear the flag on any incident that pointed at this block.
        $block->incident?->forceFill(['blocked_at' => null, 'block_id' => null])->save();

        $this->dispatch('toast', type: 'success', message: 'IP '.$block->ip.' di-unblock.');
    }

    protected function exportFilename(): string
    {
        return 'secscan-ip-blocks';
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return IpBlock::with('incident')
            ->orderByDesc('blocked_at')
            ->limit(10000)
            ->get()
            ->map(fn (IpBlock $b) => [
                'IP'         => $b->ip,
                'Status'     => $b->status,
                'Mode'       => $b->dry_run ? 'dry-run' : 'enforced',
                'Alasan'     => $b->reason,
                'CF Rule ID' => $b->cf_rule_id,
                'Otomatis'   => $b->blocked_by ? 'manual' : 'auto',
                'Di-block'   => $b->blocked_at?->format('Y-m-d H:i:s'),
                'Di-unblock' => $b->unblocked_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        $blocks = IpBlock::with('incident')
            ->when($this->search, fn ($q) => $q->where('ip', 'like', "%{$this->search}%"))
            ->when($this->filterStatus, fn ($q) => $q->where('status', $this->filterStatus))
            ->orderByDesc('blocked_at')
            ->paginate(25);

        $stats = [
            'active'  => IpBlock::where('status', IpBlock::STATUS_ACTIVE)->count(),
            'dry_run' => IpBlock::where('dry_run', true)->where('status', IpBlock::STATUS_ACTIVE)->count(),
            'removed' => IpBlock::where('status', IpBlock::STATUS_REMOVED)->count(),
        ];

        return view('nawasara-secscan::livewire.pages.ip-blocks.index', [
            'blocks' => $blocks,
            'stats'  => $stats,
        ])->layout('nawasara-ui::components.layouts.app');
    }
}
