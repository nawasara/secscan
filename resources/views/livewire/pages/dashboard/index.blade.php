<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => '#'], ['label' => 'Dashboard']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Keamanan Situs"
            description="Deteksi indikasi situs ter-retas, judi online, dan malware dari database yang dimonitor."
            :count="$this->stats['sites'] ? $this->stats['sites'].' situs bermasalah' : null">
            @if ($this->isConfigured)
                @can('secscan.scan.execute')
                    <x-nawasara-ui::icon-button
                        icon="radar"
                        tooltip="Pindai sekarang"
                        wire:click="scanNow"
                        loadingTarget="scanNow" />
                @endcan
            @endif
        </x-nawasara-ui::page-header>

        @if (! $this->isConfigured)
            <x-nawasara-ui::empty-state
                icon="lucide-shield-alert"
                title="Kredensial database belum diatur"
                description="Secscan membaca dari koneksi Database Monitor. Isi grup database-monitor di Vault terlebih dahulu.">
                <x-nawasara-ui::button color="primary" :href="url('nawasara-vault')" wire:navigate>
                    Buka Vault
                </x-nawasara-ui::button>
            </x-nawasara-ui::empty-state>
        @else
            {{-- Stat cards --}}
            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-4">
                <x-nawasara-ui::stat-card compact
                    label="Kritis"
                    :value="$this->stats['critical']"
                    color="danger"
                    icon="lucide-octagon-alert"
                    description="indikator kuat" />
                <x-nawasara-ui::stat-card compact
                    label="Peringatan"
                    :value="$this->stats['warning']"
                    color="warning"
                    icon="lucide-triangle-alert"
                    description="perlu verifikasi" />
                <x-nawasara-ui::stat-card compact
                    label="Belum ditangani"
                    :value="$this->stats['open']"
                    color="info"
                    icon="lucide-inbox" />
                <x-nawasara-ui::stat-card compact
                    label="Situs terdampak"
                    :value="$this->stats['sites']"
                    color="neutral"
                    icon="lucide-globe" />
            </div>

            {{-- Top findings preview --}}
            <x-nawasara-ui::page.card>
                <div class="flex items-center justify-between mb-3">
                    <p class="text-sm font-medium text-neutral-800 dark:text-neutral-100">Temuan Paling Mendesak</p>
                    <x-nawasara-ui::button color="neutral" variant="outline" size="sm"
                        :href="route('nawasara-secscan.findings')" wire:navigate>
                        Lihat semua
                    </x-nawasara-ui::button>
                </div>

                @forelse ($this->topFindings as $finding)
                    <div class="flex items-center justify-between gap-3 py-2 border-b border-gray-100 dark:border-neutral-700/60 last:border-0">
                        <div class="min-w-0">
                            <div class="flex items-center gap-2">
                                <x-nawasara-ui::badge :color="$finding->severityColor()">
                                    {{ ucfirst($finding->severity) }}
                                </x-nawasara-ui::badge>
                                <span class="text-sm font-medium text-neutral-800 dark:text-neutral-100 truncate">
                                    {{ $finding->site_name ?: $finding->db_name }}
                                </span>
                            </div>
                            <p class="text-xs text-neutral-500 dark:text-neutral-400 mt-0.5 truncate">
                                {{ $finding->threatLabel() }} · {{ $finding->db_name }}
                                @if ($finding->site_url) · {{ $finding->site_url }} @endif
                            </p>
                        </div>
                        <div class="text-right shrink-0">
                            <span class="text-sm font-semibold text-neutral-700 dark:text-neutral-200">{{ $finding->score }}</span>
                            <p class="text-[11px] text-neutral-400 dark:text-neutral-500">skor</p>
                        </div>
                    </div>
                @empty
                    <x-nawasara-ui::empty-state inline variant="celebrate"
                        icon="lucide-shield-check"
                        title="Tidak ada temuan aktif"
                        description="Semua situs yang dipindai bersih dari indikator yang dikenali." />
                @endforelse
            </x-nawasara-ui::page.card>
        @endif
    </x-nawasara-ui::page.container>
</div>
