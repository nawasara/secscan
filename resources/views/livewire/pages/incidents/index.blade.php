<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Incidents Agent'],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Incidents Agent"
            description="Insiden keamanan yang dilaporkan oleh nawasara-agent dari server ter-monitor." />

        <livewire:nawasara-secscan.incidents.section.table />
    </x-nawasara-ui::page.container>
</div>
