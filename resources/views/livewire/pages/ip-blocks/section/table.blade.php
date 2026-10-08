<div>
    <x-nawasara-ui::page-header
        title="Blokir IP"
        description="IP penyerang yang diblokir di Cloudflare, otomatis oleh Decision Engine atau manual oleh petugas. Blokir tidak kedaluwarsa."
        :count="$this->stats['active'] . ' aktif'">
        <x-nawasara-ui::time-window
            :window="$window" :from="$from" :to="$to"
            :presets="['7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />
        <x-nawasara-ui::export-button permission="secscan.export" tooltip="Ekspor daftar sesuai saringan" />
        <x-nawasara-ui::button color="danger"
            x-on:click="$dispatch('open-modal', { id: 'ip-block-form' })">
            <x-lucide-shield-ban class="size-4" /> Blokir IP
        </x-nawasara-ui::button>
    </x-nawasara-ui::page-header>

    {{-- Mode banner: membuat jelas bila blokir belum benar-benar diterapkan --}}
    @if (config('nawasara-secscan.autoblock.dry_run', true) && config('nawasara-secscan.autoblock.enabled', false))
        <div class="mb-4 flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-300">
            <x-lucide-flask-conical class="size-4 shrink-0" />
            <span><strong>Mode uji (dry-run) aktif.</strong> Keputusan blokir dicatat tetapi <strong>belum diterapkan di Cloudflare</strong>. Matikan <code>SECSCAN_AUTOBLOCK_DRYRUN</code> untuk menerapkannya.</span>
        </div>
    @elseif (! config('nawasara-secscan.autoblock.enabled', false))
        <div class="mb-4 flex items-center gap-2 rounded-lg border border-neutral-300 bg-neutral-50 px-4 py-3 text-sm text-neutral-600 dark:border-neutral-700 dark:bg-neutral-800/40 dark:text-neutral-400">
            <x-lucide-power-off class="size-4 shrink-0" />
            <span>Blokir otomatis <strong>nonaktif</strong> (<code>SECSCAN_AUTOBLOCK_ENABLED=false</code>). Decision Engine tidak berjalan.</span>
        </div>
    @endif

    <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
        <x-nawasara-ui::stat-card compact icon="lucide-shield-ban" label="Blokir aktif" :value="$this->stats['active']" color="danger" />
        <x-nawasara-ui::stat-card compact icon="lucide-history" label="Aktif lebih dari 30 hari" :value="$this->stats['old']" color="warning" />
        <x-nawasara-ui::stat-card compact icon="lucide-flask-conical" label="Mode uji (belum diterapkan)" :value="$this->stats['dry_run']" color="neutral" />
        <x-nawasara-ui::stat-card compact icon="lucide-shield-check" label="Sudah dicabut" :value="$this->stats['removed']" color="neutral" />
    </div>

    @php
        $statusLabels = ['active' => 'Aktif', 'removed' => 'Dicabut'];
        $sourceLabels = ['auto' => 'Otomatis', 'manual' => 'Manual'];
    @endphp

    <div class="space-y-2 mb-4">
        <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
            <div class="flex flex-wrap items-center gap-2 shrink-0">
                <x-nawasara-ui::filter-panel label="Filter"
                    :state="['filterStatus' => $filterStatus, 'filterReason' => $filterReason, 'filterSource' => $filterSource]"
                    :multiple="['filterReason']"
                    :labels="['filterStatus' => $statusLabels, 'filterReason' => $this->reasonOptions, 'filterSource' => $sourceLabels]"
                    :dimensions="['filterStatus' => 'Status', 'filterReason' => 'Alasan', 'filterSource' => 'Sumber']">
                    <x-nawasara-ui::filter-group label="Status" model="filterStatus" :items="$statusLabels" icon="lucide-shield" />
                    <x-nawasara-ui::filter-group label="Alasan" model="filterReason" :items="$this->reasonOptions" icon="lucide-bug" />
                    <x-nawasara-ui::filter-group label="Sumber" model="filterSource" :items="$sourceLabels" icon="lucide-user" />
                </x-nawasara-ui::filter-panel>
            </div>

            <x-nawasara-ui::search-input model="search" placeholder="Cari IP..." />

            {{-- Pembersihan manual: blokir tidak kedaluwarsa, jadi inilah jalan
                 keluarnya. Hanya muncul saat daftarnya sudah dipersempit,
                 supaya tidak ada yang mencabut 500 blokir dengan satu klik
                 dari tampilan bawaan. --}}
            @if ($this->hasNarrowing && $this->activeInFilter > 0)
                @can('secscan.ip-block.manage')
                    <x-nawasara-ui::button color="warning" variant="outline" class="shrink-0"
                        wire:click="unblockFiltered"
                        wire:confirm="Cabut {{ $this->activeInFilter }} blokir aktif dalam saringan ini? IP-IP tersebut bisa mengakses situs lagi.">
                        Cabut {{ $this->activeInFilter }} blokir
                    </x-nawasara-ui::button>
                @endcan
            @endif
        </div>

        <div wire:ignore data-filter-chips></div>

        @if ($search !== '')
            <div class="flex flex-wrap items-center gap-2">
                <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
            </div>
        @endif
    </div>

    <x-nawasara-ui::table stickyLast :headers="['IP', 'Alasan', 'Sumber', 'Diblokir', 'Status', '']">
        <x-slot:table>
            @forelse ($this->rows as $b)
                @php
                    $items = [
                        ['type' => 'link', 'label' => 'Linimasa IP', 'href' => route('nawasara-secscan.ip-timeline', ['ip' => $b->ip]),
                         'navigate' => true, 'icon' => 'lucide-history'],
                    ];
                    if ($b->isActive()) {
                        $items[] = ['type' => 'click', 'label' => 'Cabut blokir', 'wire:click' => 'unblock('.$b->id.')',
                            'icon' => 'lucide-shield-off', 'permission' => 'secscan.ip-block.manage',
                            'confirm' => 'Cabut blokir IP '.$b->ip.'? IP ini bisa mengakses situs lagi.'];
                    }
                @endphp
                <tr wire:key="block-{{ $b->id }}" class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                    <td class="px-6 py-4 font-mono text-sm">
                        <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $b->ip]) }}" wire:navigate
                            class="text-neutral-800 dark:text-neutral-100 hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">{{ $b->ip }}</a>
                        @if ($b->dry_run)
                            <div class="text-xs font-sans text-amber-600 dark:text-amber-400">mode uji, belum diterapkan</div>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-700 dark:text-neutral-200">{{ \Nawasara\Secscan\Models\IpBlock::reasonLabel($b->reason) }}</td>
                    <td class="px-6 py-4 text-sm text-neutral-500 dark:text-neutral-400">{{ $b->blocked_by ? 'Manual' : 'Otomatis' }}</td>
                    <td class="px-6 py-4 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                        <span title="{{ $b->blocked_at?->format('d M Y H:i:s') }}">{{ $b->blocked_at?->diffForHumans() }}</span>
                    </td>
                    <td class="px-6 py-4">
                        @if ($b->isActive())
                            <x-nawasara-ui::badge color="danger">Aktif</x-nawasara-ui::badge>
                        @else
                            <x-nawasara-ui::badge color="neutral">Dicabut</x-nawasara-ui::badge>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-right">
                        <x-nawasara-ui::dropdown-menu-action :id="$b->id" :items="$items" />
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="6" class="px-6 py-6">
                        @if ($this->hasNarrowing || $filterStatus !== \Nawasara\Secscan\Models\IpBlock::STATUS_ACTIVE)
                            <x-nawasara-ui::empty-state inline icon="lucide-search-x"
                                title="Tidak ada yang cocok" description="Ubah kata kunci, saringan, atau rentang waktunya." />
                        @else
                            <x-nawasara-ui::empty-state inline icon="lucide-shield-check" variant="celebrate"
                                title="Belum ada IP yang diblokir"
                                description="Decision Engine mencatat IP penyerang di sini saat ambang terpenuhi." />
                        @endif
                    </td>
                </tr>
            @endforelse
        </x-slot:table>
    </x-nawasara-ui::table>

    <div class="mt-4">{{ $this->rows->links() }}</div>
</div>
