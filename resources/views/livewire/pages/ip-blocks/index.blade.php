<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => route('nawasara-secscan.dashboard')], ['label' => 'Blokir IP']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <livewire:nawasara-secscan.ip-blocks.section.table />
        <livewire:nawasara-secscan.ip-blocks.section.block-form />
    </x-nawasara-ui::page.container>
</div>
