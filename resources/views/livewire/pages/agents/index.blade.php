<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Keamanan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Agen'],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Agen Keamanan"
            description="Agen nawasara-agent yang terpasang di server. Agen yang servernya sudah tidak dipakai sebaiknya dicabut.">
        </x-nawasara-ui::page-header>

        <livewire:nawasara-secscan.agents.section.stats />
        <livewire:nawasara-secscan.agents.section.table />
    </x-nawasara-ui::page.container>
</div>
