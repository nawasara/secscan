<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Keamanan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Insiden'],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Insiden"
            description="Serangan yang dilaporkan agen dari server yang dipantau. IP sumber yang memenuhi ambang diblokir otomatis." />

        <livewire:nawasara-secscan.incidents.section.table />
    </x-nawasara-ui::page.container>
</div>
