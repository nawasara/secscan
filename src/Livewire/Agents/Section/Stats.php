<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\On;
use Livewire\Component;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\SecurityIncident;

class Stats extends Component
{
    #[On('agent-registered')]
    public function refresh(): void {}

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.stats', [
            'totalAgents' => Agent::count(),
            'onlineAgents' => Agent::online()->count(),
            'offlineAgents' => Agent::offline()->count(),
            'criticalToday' => SecurityIncident::where('severity', SecurityIncident::SEVERITY_CRITICAL)->today()->count(),
            'highToday' => SecurityIncident::where('severity', SecurityIncident::SEVERITY_HIGH)->today()->count(),
        ]);
    }
}
