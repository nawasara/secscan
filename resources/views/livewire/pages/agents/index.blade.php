<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Agents'],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Security Agents"
            description="Daftar agent nawasara-agent yang ter-install di server">
        </x-nawasara-ui::page-header>

        <livewire:nawasara-secscan.agents.section.stats />
        <livewire:nawasara-secscan.agents.section.table />
    </x-nawasara-ui::page.container>
</div>
