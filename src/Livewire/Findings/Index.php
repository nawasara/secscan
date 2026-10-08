<?php

namespace Nawasara\Secscan\Livewire\Findings;

use Livewire\Component;

/**
 * Temuan Website: shell only. The list lives in Section\Table, the detail and
 * triage modal in Section\Detail; they talk through Livewire events.
 */
class Index extends Component
{
    public function render()
    {
        return view('nawasara-secscan::livewire.pages.findings.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
