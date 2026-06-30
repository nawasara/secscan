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
        $threeMinAgo = now()->subMinutes(3);

        $totalAgents   = Agent::count();
        $onlineAgents  = Agent::where('last_seen_at', '>=', $threeMinAgo)->count();
        $offlineAgents = Agent::where('last_seen_at', '<', $threeMinAgo)->whereNotNull('last_seen_at')->count();

        $criticalToday = SecurityIncident::where('severity', 'critical')
            ->whereDate('detected_at', today())
            ->count();

        $highToday = SecurityIncident::where('severity', 'high')
            ->whereDate('detected_at', today())
            ->count();

        return view('nawasara-secscan::livewire.pages.agents.section.stats', [
            'totalAgents'   => $totalAgents,
            'onlineAgents'  => $onlineAgents,
            'offlineAgents' => $offlineAgents,
            'criticalToday' => $criticalToday,
            'highToday'     => $highToday,
        ]);
    }
}
