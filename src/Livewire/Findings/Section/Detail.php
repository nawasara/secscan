<?php

namespace Nawasara\Secscan\Livewire\Findings\Section;

use Livewire\Attributes\Computed;
use Livewire\Attributes\On;
use Livewire\Component;
use Nawasara\Secscan\Models\SecscanFinding;
use Nawasara\Secscan\Services\FindingTriage;

/** Detail + triage modal for one finding, opened from Section\Table. */
class Detail extends Component
{
    public ?int $detailId = null;

    public string $triageReason = '';

    #[On('secscan-finding-open')]
    public function open(int $id): void
    {
        $this->detailId = $id;
        $this->triageReason = '';
        unset($this->detail);
        $this->dispatch('modal-open:secscan-finding-detail');
    }

    public function acknowledge(): void
    {
        $this->triage(SecscanFinding::STATUS_ACKNOWLEDGED, 'Diakui, sedang ditangani.');
    }

    public function markFalsePositive(): void
    {
        $this->triage(SecscanFinding::STATUS_FALSE_POSITIVE, 'Ditandai false positive.');
    }

    public function resolve(): void
    {
        $this->triage(SecscanFinding::STATUS_RESOLVED, 'Ditandai selesai.');
    }

    protected function triage(string $to, string $fallbackReason): void
    {
        $this->authorize('secscan.finding.triage');

        $finding = SecscanFinding::findOrFail($this->detailId);
        $reason = trim($this->triageReason) !== '' ? trim($this->triageReason) : $fallbackReason;

        app(FindingTriage::class)->transition($finding, $to, $reason, auth()->id());

        $this->triageReason = '';
        $this->dispatch('modal-close:secscan-finding-detail');
        $this->dispatch('secscan-finding-updated');
        $this->dispatch('toast', ['type' => 'success', 'message' => 'Status temuan diperbarui.']);
    }

    #[Computed]
    public function detail(): ?SecscanFinding
    {
        return $this->detailId ? SecscanFinding::with('histories')->find($this->detailId) : null;
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.findings.section.detail');
    }
}
