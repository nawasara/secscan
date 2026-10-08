<?php

namespace Nawasara\Secscan\Livewire\IpBlocks;

use Livewire\Component;

/**
 * Blokir IP: shell only. The list, filters and bulk cleanup live in
 * Section\Table; the manual-block modal in Section\BlockForm.
 */
class Index extends Component
{
    public function mount(): void
    {
        $this->authorize('secscan.ip-block.manage');
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.ip-blocks.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
