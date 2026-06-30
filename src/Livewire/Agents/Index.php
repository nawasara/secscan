<?php

namespace Nawasara\Secscan\Livewire\Agents;

use Livewire\Component;

class Index extends Component
{
    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
