<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => '#'], ['label' => 'Temuan']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Temuan Keamanan"
            description="Indikasi situs ter-retas / judi online / malware dari pemindaian database."
            :count="$this->rows->total() . ' temuan'" />

        @php
            $severityLabels = ['critical' => 'Kritis', 'warning' => 'Peringatan', 'info' => 'Info'];
            $statusLabels = \Nawasara\Secscan\Models\SecscanFinding::statusLabels();
            $threatLabels = $this->threatOptions;
        @endphp

        {{-- Toolbar: satu filter-panel (severity/status/threat semua multi-select) --}}
        <div class="space-y-2 mb-4">
            <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
                <div class="flex flex-wrap items-center gap-2 shrink-0">
                    <x-nawasara-ui::filter-panel label="Filter" :state="[
                        'severityFilter' => $severityFilter,
                        'statusFilter' => $statusFilter,
                        'threatFilter' => $threatFilter,
                    ]" :multiple="['severityFilter', 'statusFilter', 'threatFilter']" :labels="[
                        'severityFilter' => $severityLabels,
                        'statusFilter' => $statusLabels,
                        'threatFilter' => $threatLabels,
                    ]" :dimensions="[
                        'severityFilter' => 'Severity',
                        'statusFilter' => 'Status',
                        'threatFilter' => 'Jenis Ancaman',
                    ]">
                        <x-nawasara-ui::filter-group label="Severity" model="severityFilter" :items="$severityLabels"
                            icon="lucide-octagon-alert" />
                        <x-nawasara-ui::filter-group label="Status" model="statusFilter" :items="$statusLabels"
                            icon="lucide-list-checks" />
                        <x-nawasara-ui::filter-group label="Jenis Ancaman" model="threatFilter" :items="$threatLabels"
                            icon="lucide-bug" />
                    </x-nawasara-ui::filter-panel>
                </div>

                <x-nawasara-ui::search-input model="search" placeholder="Cari situs, database, URL..." />
            </div>

            <div wire:ignore data-filter-chips></div>

            @if ($search !== '')
                <div class="flex flex-wrap items-center gap-2">
                    <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
                </div>
            @endif
        </div>

        {{-- Table --}}
        <x-nawasara-ui::table stickyLast :headers="['Severity', 'Situs', 'Jenis', 'Skor', 'Status', 'Terakhir', '']">
            <x-slot:table>
                @forelse ($this->rows as $finding)
                    <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-700/40">
                        <td class="px-4 py-2.5">
                            <x-nawasara-ui::badge :color="$finding->severityColor()">
                                {{ $severityLabels[$finding->severity] ?? ucfirst($finding->severity) }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-2.5">
                            <div class="text-sm font-medium text-neutral-800 dark:text-neutral-100 truncate max-w-[260px]">
                                {{ $finding->site_name ?: $finding->db_name }}
                            </div>
                            <div class="text-xs text-neutral-400 dark:text-neutral-500 truncate max-w-[260px]">
                                {{ $finding->db_name }}@if ($finding->site_url) · {{ $finding->site_url }} @endif
                            </div>
                        </td>
                        <td class="px-4 py-2.5 text-sm text-neutral-600 dark:text-neutral-300">
                            {{ $finding->threatLabel() }}
                        </td>
                        <td class="px-4 py-2.5 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                            {{ $finding->score }}
                        </td>
                        <td class="px-4 py-2.5">
                            <x-nawasara-ui::badge :color="$finding->statusColor()">{{ $finding->statusLabel() }}</x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-2.5 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            {{ $finding->last_detected_at?->diffForHumans() ?? '—' }}
                        </td>
                        <td class="px-4 py-2.5 text-right">
                            <x-nawasara-ui::icon-button icon="eye" tooltip="Detail & tindak lanjut" placement="left"
                                wire:click="openDetail({{ $finding->id }})" />
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="7" class="px-4 py-6">
                            <x-nawasara-ui::empty-state inline variant="celebrate" icon="lucide-shield-check"
                                title="Tidak ada temuan" description="Tidak ada indikator yang cocok dengan filter saat ini." />
                        </td>
                    </tr>
                @endforelse
            </x-slot:table>
        </x-nawasara-ui::table>

        <div class="mt-4">
            {{ $this->rows->links() }}
        </div>

        {{-- Detail + triage modal --}}
        <x-nawasara-ui::modal id="secscan-finding-detail" title="Detail Temuan" maxWidth="2xl">
            @if ($this->detail)
                @php $d = $this->detail; @endphp
                <div class="space-y-4">
                    <div class="flex items-center gap-2 flex-wrap">
                        <x-nawasara-ui::badge :color="$d->severityColor()">{{ ucfirst($d->severity) }}</x-nawasara-ui::badge>
                        <x-nawasara-ui::badge :color="$d->statusColor()">{{ $d->statusLabel() }}</x-nawasara-ui::badge>
                        <span class="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Skor {{ $d->score }}</span>
                    </div>

                    <dl class="grid grid-cols-2 gap-3 text-sm">
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">Situs</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->site_name ?: '—' }}</dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">Database</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->db_name }}</dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">URL</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100 break-all">{{ $d->site_url ?: '—' }}</dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">Jenis</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->threatLabel() }}</dd>
                        </div>
                    </dl>

                    {{-- Evidence --}}
                    @php $ev = $d->evidence ?? []; @endphp
                    <div>
                        <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-2">Bukti</p>

                        {{-- Judol post links: clickable ?p=ID to the live page --}}
                        @if (! empty($ev['samples']))
                            <div class="mb-3">
                                <p class="text-xs text-neutral-600 dark:text-neutral-300 mb-1">
                                    {{ $ev['published_judol_posts'] ?? count($ev['samples']) }} postingan judi online terbit
                                    @if (($ev['published_judol_posts'] ?? 0) > count($ev['samples']))
                                        <span class="text-neutral-400">(menampilkan {{ count($ev['samples']) }} contoh)</span>
                                    @endif
                                </p>
                                <ul class="space-y-1.5">
                                    @foreach ($ev['samples'] as $s)
                                        <li class="text-sm">
                                            <div class="text-neutral-800 dark:text-neutral-100 truncate">{{ $s['title'] ?? '—' }}</div>
                                            @if (! empty($s['url']))
                                                <a href="{{ $s['url'] }}" target="_blank" rel="noopener noreferrer"
                                                    class="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400 hover:underline break-all">
                                                    <x-lucide-external-link class="size-3 shrink-0" />
                                                    {{ $s['url'] }}
                                                </a>
                                            @endif
                                        </li>
                                    @endforeach
                                </ul>
                            </div>
                        @endif

                        {{-- Other signals as readable lines --}}
                        @php
                            $otherKeys = [
                                'injected_posts' => 'Postingan dengan konten ter-inject',
                                'suspicious_autoload_options' => 'Opsi autoload mencurigakan',
                                'offsite_urls' => 'URL mengarah ke luar domain resmi',
                                'recently_registered_admins' => 'Admin baru terdaftar (≤14 hari)',
                                'admin_count' => 'Jumlah admin',
                                'blogname' => 'Nama situs (blogname)',
                                'note' => 'Catatan',
                            ];
                        @endphp
                        @foreach ($otherKeys as $k => $label)
                            @if (isset($ev[$k]) && $ev[$k] !== [] && $ev[$k] !== '')
                                <div class="text-xs text-neutral-600 dark:text-neutral-300 mb-0.5">
                                    <span class="text-neutral-400 dark:text-neutral-500">{{ $label }}:</span>
                                    {{ is_array($ev[$k]) ? json_encode($ev[$k], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : $ev[$k] }}
                                </div>
                            @endif
                        @endforeach

                        {{-- Raw evidence (collapsible, for completeness) --}}
                        <details class="mt-2">
                            <summary class="text-xs text-neutral-400 dark:text-neutral-500 cursor-pointer hover:text-neutral-600 dark:hover:text-neutral-300">Data mentah</summary>
                            <pre class="text-xs bg-gray-50 dark:bg-neutral-900 border border-gray-200 dark:border-neutral-700 rounded-lg p-3 overflow-x-auto text-neutral-700 dark:text-neutral-300 mt-1">{{ json_encode($ev, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) }}</pre>
                        </details>
                    </div>

                    {{-- History --}}
                    @if ($d->histories->isNotEmpty())
                        <div>
                            <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-1">Riwayat</p>
                            <ul class="space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                                @foreach ($d->histories->sortByDesc('created_at') as $h)
                                    <li>
                                        <span class="text-neutral-400">{{ $h->created_at?->diffForHumans() }}</span>
                                        — {{ $h->status_from ?? 'baru' }} → <strong>{{ $h->status_to }}</strong>
                                        @if ($h->reason) · {{ $h->reason }} @endif
                                    </li>
                                @endforeach
                            </ul>
                        </div>
                    @endif

                    @can('secscan.finding.triage')
                        @if ($d->isActive())
                            <div class="border-t border-gray-200 dark:border-neutral-700 pt-3 space-y-2">
                                <x-nawasara-ui::form.textarea wire:model="triageReason" label="Catatan (opsional)" :rows="2"
                                    placeholder="Alasan / tindak lanjut..." />
                            </div>
                        @endif
                    @endcan
                </div>

                <x-slot:footer>
                    @can('secscan.finding.triage')
                        @if ($d->isActive())
                            @if ($d->status === \Nawasara\Secscan\Models\SecscanFinding::STATUS_OPEN)
                                <x-nawasara-ui::button color="warning" variant="outline" wire:click="acknowledge({{ $d->id }})">
                                    Akui
                                </x-nawasara-ui::button>
                            @endif
                            <x-nawasara-ui::button color="neutral" variant="outline" wire:click="markFalsePositive({{ $d->id }})">
                                False Positive
                            </x-nawasara-ui::button>
                            <x-nawasara-ui::button color="success" wire:click="resolve({{ $d->id }})">
                                Tandai Selesai
                            </x-nawasara-ui::button>
                        @endif
                    @endcan
                </x-slot:footer>
            @endif
        </x-nawasara-ui::modal>
    </x-nawasara-ui::page.container>
</div>
