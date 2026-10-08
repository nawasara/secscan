<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => route('nawasara-secscan.dashboard')], ['label' => 'Temuan Website']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <livewire:nawasara-secscan.findings.section.table />
        <livewire:nawasara-secscan.findings.section.detail />
    </x-nawasara-ui::page.container>
</div>
