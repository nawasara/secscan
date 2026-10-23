<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => route('nawasara-secscan.dashboard')], ['label' => 'Versi PHP']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <livewire:nawasara-secscan.php-runtimes.section.table />
    </x-nawasara-ui::page.container>
</div>
