<?php

namespace Nawasara\Secscan\Livewire\Incidents;

use Livewire\Component;

class Index extends Component
{
    public function render()
    {
        return view('nawasara-secscan::livewire.pages.incidents.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
