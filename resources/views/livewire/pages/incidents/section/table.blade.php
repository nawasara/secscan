<div>
    @php
        $severityLabels = \Nawasara\Secscan\Models\SecurityIncident::severityLabels();
    @endphp

    {{-- Toolbar: filter-panel kiri (shrink-0) + time-window, search kanan (flex-1). --}}
    <div class="space-y-2 mb-4">
        <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
            <div class="flex flex-wrap items-center gap-2 shrink-0">
                <x-nawasara-ui::filter-panel
                    label="Filter"
                    :showChips="false"
                    :state="['filterSeverity' => $filterSeverity, 'filterType' => $filterType]"
                    :dimensions="['filterSeverity' => 'Tingkat', 'filterType' => 'Jenis Serangan']">
                    <x-nawasara-ui::filter-group
                        label="Tingkat"
                        model="filterSeverity"
                        :items="$severityLabels"
                        icon="lucide-octagon-alert" />
                    <x-nawasara-ui::filter-group
                        label="Jenis Serangan"
                        model="filterType"
                        :items="$typeOptions"
                        icon="lucide-shield-alert" />
                </x-nawasara-ui::filter-panel>

                <x-nawasara-ui::time-window
                    :window="$window" :from="$from" :to="$to"
                    :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />

                <x-nawasara-ui::export-button
                    permission="secscan.export"
                    tooltip="Ekspor insiden sesuai saringan (maks 10.000 baris)" />
            </div>

            <x-nawasara-ui::search-input model="search" placeholder="Cari IP sumber..." />
        </div>

        {{-- Chip saringan dirender di SERVER (Livewire), supaya bertahan saat
             pindah halaman. filter-panel memakai :showChips="false" karena
             chip teleport Alpine-nya ter-reset saat morph paginasi. --}}
        @if ($this->hasFilters())
            <div class="flex flex-wrap items-center gap-2">
                @if ($search !== '')
                    <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
                @endif
                @if ($filterSeverity !== '')
                    <x-nawasara-ui::filter-chip label="Tingkat: {{ $severityLabels[$filterSeverity] ?? $filterSeverity }}" model="filterSeverity" />
                @endif
                @if ($filterType !== '')
                    <x-nawasara-ui::filter-chip label="Jenis: {{ \Nawasara\Secscan\Models\SecurityIncident::labelForType($filterType) }}" model="filterType" />
                @endif
            </div>
        @endif
    </div>

    {{-- Tujuh kolom, bukan sepuluh: skor ikut di kolom Kejadian, agen di bawah
         target. Sepuluh kolom membuat tabel menggulir ke samping di layar
         laptop dan memotong kolom yang paling penting. --}}
    <x-nawasara-ui::table stickyLast
        :headers="['Tingkat', 'Serangan', 'IP Sumber', 'Target', 'Kejadian', 'Terakhir', '']">
        <x-slot:table>
            @forelse ($incidents as $inc)
                @php $incHosts = collect($inc->evidence ?? [])->pluck('host')->filter()->unique()->values(); @endphp
                <tr wire:key="inc-{{ $inc->id }}" class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                    <td class="px-6 py-4">
                        <x-nawasara-ui::badge :color="$inc->severityColor()">{{ $inc->severityLabel() }}</x-nawasara-ui::badge>
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-700 dark:text-neutral-200">
                        <span class="inline-flex flex-wrap items-center gap-1.5">
                            {{ $inc->typeLabel() }}
                            @if ($inc->correlated)
                                <x-nawasara-ui::badge color="danger">Rantai</x-nawasara-ui::badge>
                            @endif
                            @if ($inc->mitre_technique)
                                <a href="{{ $inc->mitreUrl() }}" target="_blank" rel="noopener"
                                   title="MITRE ATT&CK: {{ $inc->mitreName() }}"
                                   class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-mono font-medium bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300 hover:bg-sky-100 dark:hover:bg-sky-900/50">
                                    {{ $inc->mitre_technique }}
                                </a>
                            @endif
                        </span>
                    </td>
                    <td class="px-6 py-4 font-mono text-sm text-neutral-700 dark:text-neutral-200">
                        @if ($inc->source_ip)
                            <span class="inline-flex items-center gap-1.5">
                                <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $inc->source_ip]) }}" wire:navigate
                                   class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">{{ $inc->source_ip }}</a>
                                @if (isset($blockedIps[$inc->source_ip]))
                                    <x-nawasara-ui::badge color="danger" title="IP ini sedang diblokir di Cloudflare">Diblokir</x-nawasara-ui::badge>
                                @endif
                            </span>
                        @else
                            <span class="font-sans text-neutral-400 dark:text-neutral-500 italic">berkas di server</span>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm">
                        @if ($incHosts->isNotEmpty())
                            <span class="inline-flex flex-wrap items-center gap-1">
                                @foreach ($incHosts->take(2) as $h)
                                    <span class="inline-flex items-center gap-1 rounded bg-amber-50 dark:bg-amber-900/30 px-1.5 py-0.5 font-mono text-xs text-amber-700 dark:text-amber-300"
                                          title="Target: {{ $h }}">
                                        <x-lucide-globe class="size-3" />{{ $h }}
                                    </span>
                                @endforeach
                                @if ($incHosts->count() > 2)
                                    <span class="text-xs text-neutral-400 dark:text-neutral-500" title="{{ $incHosts->implode(', ') }}">+{{ $incHosts->count() - 2 }}</span>
                                @endif
                            </span>
                        @endif
                        <div class="text-xs text-neutral-500 dark:text-neutral-400 {{ $incHosts->isNotEmpty() ? 'mt-1' : '' }}">
                            @if ($inc->agent)
                                <a href="{{ route('nawasara-secscan.agents.show', $inc->agent->agent_id) }}" wire:navigate
                                   class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">{{ $inc->agent->name }}</a>
                                @if ($inc->agent->trashed()) <span class="text-neutral-400 dark:text-neutral-500">(dicabut)</span> @endif
                            @else
                                -
                            @endif
                        </div>
                    </td>
                    <td class="px-6 py-4 text-sm whitespace-nowrap">
                        @if ($inc->occurrences > 1)
                            <x-nawasara-ui::badge color="warning">×{{ number_format($inc->occurrences) }}</x-nawasara-ui::badge>
                        @else
                            <span class="text-neutral-500 dark:text-neutral-400">1×</span>
                        @endif
                        <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">skor {{ $inc->score }}</div>
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                        <span title="Pertama {{ $inc->detected_at?->format('d M Y H:i') }}, terakhir {{ ($inc->last_seen_at ?? $inc->detected_at)?->format('d M Y H:i') }}">
                            {{ ($inc->last_seen_at ?? $inc->detected_at)?->diffForHumans() }}
                        </span>
                    </td>
                    <td class="px-6 py-4 text-right">
                        <x-nawasara-ui::dropdown-menu-action :id="$inc->id" :items="[
                            ['type' => 'click', 'label' => 'Lihat bukti', 'wire:click' => 'openDetail('.$inc->id.')', 'modal' => 'incident-detail-modal', 'icon' => 'lucide-eye'],
                        ]" />
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="7" class="px-6 py-6">
                        @if ($this->hasFilters())
                            <x-nawasara-ui::empty-state inline icon="lucide-search-x"
                                title="Tidak ada yang cocok" description="Ubah kata kunci atau saringannya." />
                        @else
                            <x-nawasara-ui::empty-state inline icon="lucide-shield-check" variant="celebrate"
                                title="Tidak ada insiden dalam rentang waktu ini"
                                description="Agen belum melaporkan serangan. Bila ini terasa janggal, periksa apakah agennya masih online di halaman Agen." />
                        @endif
                    </td>
                </tr>
            @endforelse
        </x-slot:table>
    </x-nawasara-ui::table>

    <div class="mt-4">
        {{ $incidents->links() }}
    </div>

    {{-- Modal bukti insiden --}}
    <x-nawasara-ui::modal id="incident-detail-modal" title="Detail Insiden">
        @if ($selectedIncident)
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-3 text-sm">
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Jenis</p>
                        <p class="text-neutral-800 dark:text-neutral-100 font-medium">{{ $selectedIncident->typeLabel() }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Tingkat</p>
                        <x-nawasara-ui::badge :color="$selectedIncident->severityColor()">{{ $selectedIncident->severityLabel() }}</x-nawasara-ui::badge>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">IP Sumber</p>
                        <p class="font-mono text-neutral-800 dark:text-neutral-100">{{ $selectedIncident->source_ip ?? '-' }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Skor</p>
                        <p class="font-semibold text-neutral-800 dark:text-neutral-100">{{ $selectedIncident->score }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Terdeteksi Pertama</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $selectedIncident->detected_at?->format('d M Y H:i:s') }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Terakhir Terlihat</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ ($selectedIncident->last_seen_at ?? $selectedIncident->detected_at)?->format('d M Y H:i:s') }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Jumlah Kejadian</p>
                        <p class="font-semibold text-neutral-800 dark:text-neutral-100">{{ number_format($selectedIncident->occurrences) }}×</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Agen</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $selectedIncident->agent?->name ?? '-' }}</p>
                    </div>
                    @if ($selectedIncident->mitre_technique)
                        <div class="col-span-2">
                            <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Teknik MITRE ATT&CK</p>
                            <a href="{{ $selectedIncident->mitreUrl() }}" target="_blank" rel="noopener"
                               class="inline-flex items-center gap-1.5 text-sm text-sky-600 dark:text-sky-400 hover:underline">
                                <span class="font-mono font-medium">{{ $selectedIncident->mitre_technique }}</span>
                                <span class="text-neutral-500 dark:text-neutral-400">· {{ $selectedIncident->mitreName() }}</span>
                                <x-lucide-external-link class="size-3.5" />
                            </a>
                        </div>
                    @endif
                </div>

                @if ($selectedIncident->evidence)
                    @php
                        $evHosts = collect($selectedIncident->evidence)->pluck('host')->filter()->unique()->values();
                    @endphp

                    @if ($evHosts->isNotEmpty())
                        <div>
                            <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-2">Target (Subdomain)</p>
                            <div class="flex flex-wrap gap-1.5">
                                @foreach ($evHosts as $h)
                                    <span class="inline-flex items-center gap-1 rounded-md bg-amber-50 dark:bg-amber-900/30 px-2 py-1 text-xs font-mono font-medium text-amber-700 dark:text-amber-300">
                                        <x-lucide-globe class="size-3" />{{ $h }}
                                    </span>
                                @endforeach
                            </div>
                        </div>
                    @endif

                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-2">Bukti</p>
                        <div class="space-y-2">
                            @foreach ($selectedIncident->evidence as $ev)
                                <div class="bg-neutral-50 dark:bg-neutral-900 rounded-lg p-3 text-xs font-mono">
                                    <div class="text-neutral-400 dark:text-neutral-500 mb-1 flex flex-wrap items-center gap-x-1.5">
                                        <span>{{ $ev['timestamp'] ?? '' }}</span>
                                        @if (!empty($ev['matched_rule']))
                                            · <span class="text-emerald-600 dark:text-emerald-400">{{ $ev['matched_rule'] }}</span>
                                        @endif
                                        @if (!empty($ev['host']))
                                            · <span class="text-amber-600 dark:text-amber-400">{{ $ev['host'] }}</span>
                                        @endif
                                    </div>
                                    <div class="text-neutral-800 dark:text-neutral-200 break-all">{{ $ev['raw'] ?? json_encode($ev) }}</div>
                                </div>
                            @endforeach
                        </div>
                    </div>
                @endif

                @if ($selectedIncident->correlated && $selectedIncident->correlated_group_id)
                    <div class="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800/50">
                        <x-lucide-link-2 class="size-4 text-red-600 dark:text-red-400 shrink-0" />
                        <p class="text-xs text-red-700 dark:text-red-300">
                            Insiden ini bagian dari rantai serangan (grup: <span class="font-mono">{{ $selectedIncident->correlated_group_id }}</span>)
                        </p>
                    </div>
                @endif
            </div>

            <x-slot:footer>
                @if ($selectedIncident->source_ip)
                    <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $selectedIncident->source_ip]) }}"
                       wire:navigate
                       class="text-sm text-emerald-600 dark:text-emerald-400 hover:underline">
                        Lihat semua insiden dari IP ini →
                    </a>
                @else
                    <span class="text-sm text-neutral-400 dark:text-neutral-500">
                        Tidak ada IP sumber (temuan berkas di server)
                    </span>
                @endif
            </x-slot:footer>
        @else
            <x-nawasara-ui::loading />
        @endif
    </x-nawasara-ui::modal>
</div>
