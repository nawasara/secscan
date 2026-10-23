<div>
    <x-nawasara-ui::page-header
        title="Versi PHP"
        description="Versi PHP di seluruh situs dan server, dipindai dari luar, dibaca dari server WHM, dan dilaporkan agen. Acuan tambalan: {{ config('nawasara-secscan.php_monitor.advisory') }}."
        :count="($this->stats['vulnerable'] + $this->stats['eol']) . ' perlu ditindak'">
        <x-nawasara-ui::export-button permission="secscan.export" tooltip="Ekspor daftar sesuai saringan" />
        @can('secscan.scan.execute')
            <x-nawasara-ui::button color="primary" wire:click="scanNow" wire:loading.attr="disabled">
                <x-lucide-scan-search class="size-4" /> Pindai Sekarang
            </x-nawasara-ui::button>
        @endcan
    </x-nawasara-ui::page-header>

    <div class="grid grid-cols-2 md:grid-cols-5 gap-2 mb-4">
        <x-nawasara-ui::stat-card compact icon="lucide-shield-alert" label="Rentan, tambalan ada" :value="$this->stats['vulnerable']" color="danger" />
        <x-nawasara-ui::stat-card compact icon="lucide-calendar-x" label="Tidak didukung lagi" :value="$this->stats['eol']" color="warning" />
        <x-nawasara-ui::stat-card compact icon="lucide-eye-off" label="Versi tersembunyi" :value="$this->stats['hidden']" color="neutral" />
        <x-nawasara-ui::stat-card compact icon="lucide-shield-check" label="Aman" :value="$this->stats['safe']" color="success" />
        <x-nawasara-ui::stat-card compact icon="lucide-megaphone" label="Memamerkan versi" :value="$this->stats['exposes']" color="neutral" />
    </div>

    <p class="mb-4 text-xs text-neutral-500 dark:text-neutral-400">
        <strong>Tidak didukung</strong> berarti cabang PHP-nya tidak lagi mendapat tambalan resmi; perbaikannya pindah ke PHP 8.3 atau lebih baru.
        <strong>Versi tersembunyi</strong> berarti PHP terdeteksi dari luar tetapi versinya hanya terbaca dari dalam (server WHM atau agen).
        @if ($this->lastScan)
            Terakhir diperbarui {{ \Illuminate\Support\Carbon::parse($this->lastScan)->diffForHumans() }}.
        @endif
    </p>

    @php
        $statusLabels = [
            'vulnerable' => \Nawasara\Secscan\Support\PhpPatchLevels::label('vulnerable'),
            'eol' => \Nawasara\Secscan\Support\PhpPatchLevels::label('eol'),
            'hidden' => \Nawasara\Secscan\Support\PhpPatchLevels::label('hidden'),
            'safe' => \Nawasara\Secscan\Support\PhpPatchLevels::label('safe'),
        ];
        $sourceLabels = ['external' => 'Dari luar', 'whm' => 'Server WHM', 'agent' => 'Agen'];
    @endphp

    <div class="space-y-2 mb-4">
        <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
            <div class="flex flex-wrap items-center gap-2 shrink-0">
                <x-nawasara-ui::filter-panel label="Filter"
                    :state="['filterStatus' => $filterStatus, 'filterSource' => $filterSource]"
                    :multiple="['filterStatus']"
                    :labels="['filterStatus' => $statusLabels, 'filterSource' => $sourceLabels]"
                    :dimensions="['filterStatus' => 'Status', 'filterSource' => 'Sumber']">
                    <x-nawasara-ui::filter-group label="Status" model="filterStatus" :items="$statusLabels" icon="lucide-shield" />
                    <x-nawasara-ui::filter-group label="Sumber" model="filterSource" :items="$sourceLabels" icon="lucide-radar" />
                </x-nawasara-ui::filter-panel>
            </div>

            <x-nawasara-ui::search-input model="search" placeholder="Cari situs, server, atau versi..." />
        </div>

        <div wire:ignore data-filter-chips></div>

        @if ($search !== '')
            <div class="flex flex-wrap items-center gap-2">
                <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
            </div>
        @endif
    </div>

    <x-nawasara-ui::table stickyLast :headers="['Sasaran', 'Sumber', 'Versi PHP', 'Status', 'Terakhir terlihat', '']">
        <x-slot:table>
            @forelse ($this->rows as $r)
                @php
                    $target = $levels->targetFor($r->php_version);
                    $items = [
                        ['type' => 'click', 'label' => 'Hapus', 'wire:click' => 'deleteRuntime('.$r->id.')',
                         'icon' => 'lucide-trash-2', 'permission' => 'secscan.finding.triage',
                         'confirm' => 'Hapus baris '.$r->target.'? Pemindaian berikutnya menambahkannya lagi bila masih ada.'],
                    ];
                @endphp
                <tr wire:key="php-{{ $r->id }}" class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                    <td class="px-6 py-4 text-sm">
                        <div class="font-medium text-neutral-800 dark:text-neutral-100">{{ $r->target }}</div>
                        @if ($r->exposes_version)
                            <div class="text-xs text-amber-600 dark:text-amber-400">memamerkan versi lewat header X-Powered-By</div>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-700 dark:text-neutral-200">
                        {{ \Nawasara\Secscan\Models\PhpRuntime::sourceLabel($r->source) }}
                        @if ($r->origin !== '')
                            <div class="text-xs text-neutral-500 dark:text-neutral-400">{{ $r->origin }}</div>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm whitespace-nowrap">
                        <span class="font-mono text-neutral-800 dark:text-neutral-100">{{ $r->php_version ?? '-' }}</span>
                        @if ($r->handler)
                            <div class="text-xs text-neutral-500 dark:text-neutral-400">{{ $r->handler }}</div>
                        @endif
                    </td>
                    <td class="px-6 py-4">
                        <x-nawasara-ui::badge :color="\Nawasara\Secscan\Support\PhpPatchLevels::color($r->status)">
                            {{ \Nawasara\Secscan\Support\PhpPatchLevels::label($r->status) }}
                        </x-nawasara-ui::badge>
                        @if ($r->status === 'vulnerable' && $target)
                            <div class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">naikkan ke {{ $target }}</div>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                        <span title="{{ $r->last_seen_at?->format('d M Y H:i') }}">{{ $r->last_seen_at?->diffForHumans() }}</span>
                    </td>
                    <td class="px-6 py-4 text-right">
                        <x-nawasara-ui::dropdown-menu-action :id="$r->id" :items="$items" />
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="6" class="px-6 py-6">
                        @if ($this->hasNarrowing)
                            <x-nawasara-ui::empty-state inline icon="lucide-search-x"
                                title="Tidak ada yang cocok" description="Ubah kata kunci atau saringannya." />
                        @else
                            <x-nawasara-ui::empty-state inline icon="lucide-scan-search"
                                title="Belum pernah dipindai"
                                description="Pemindaian berjalan otomatis tiap pagi. Tekan Pindai Sekarang untuk menjalankannya sekarang." />
                        @endif
                    </td>
                </tr>
            @endforelse
        </x-slot:table>
    </x-nawasara-ui::table>

    <div class="mt-4">{{ $this->rows->links() }}</div>
</div>
