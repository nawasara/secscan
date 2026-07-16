<div>
    {{-- Toolbar: filter-panel kiri (shrink-0) + time-window, search kanan (flex-1). --}}
    <div class="space-y-2 mb-4">
        <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
            <div class="flex flex-wrap items-center gap-2 shrink-0">
                <x-nawasara-ui::filter-panel
                    label="Filter"
                    :state="['filterSeverity' => $filterSeverity, 'filterType' => $filterType]"
                    :dimensions="['filterSeverity' => 'Severity', 'filterType' => 'Tipe Insiden']">

                    <x-nawasara-ui::filter-group
                        label="Severity"
                        model="filterSeverity"
                        :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'info' => 'Info']"
                        icon="lucide-octagon-alert" />

                    <x-nawasara-ui::filter-group
                        label="Tipe Insiden"
                        model="filterType"
                        :items="$typeOptions"
                        icon="lucide-shield-alert" />

                </x-nawasara-ui::filter-panel>

                <x-nawasara-ui::time-window
                    :window="$window" :from="$from" :to="$to"
                    :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />

                <x-nawasara-ui::export-button
                    permission="secscan.export"
                    tooltip="Ekspor insiden (maks 10.000 baris)" />
            </div>

            <x-nawasara-ui::search-input model="search" placeholder="Cari IP sumber…" />
        </div>

        <div wire:ignore data-filter-chips></div>

        @if ($search !== '')
            <div class="flex flex-wrap items-center gap-2">
                <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
            </div>
        @endif
    </div>

    <x-nawasara-ui::page.card>
        @if ($incidents->isEmpty())
            <x-nawasara-ui::empty-state
                icon="lucide-shield-check"
                variant="celebrate"
                title="Tidak ada insiden"
                description="Belum ada insiden yang dilaporkan oleh agent." />
        @else
            <x-nawasara-ui::table stickyLast
                :headers="['Severity', 'Tipe', 'Source IP', 'Score', 'Kejadian', 'Agent', 'Terdeteksi', 'Terakhir', '']">
                <x-slot:table>
                    @foreach ($incidents as $inc)
                        <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td class="px-4 py-3">
                                <x-nawasara-ui::badge :color="$inc->severityColor()">
                                    {{ ucfirst($inc->severity) }}
                                </x-nawasara-ui::badge>
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-700 dark:text-neutral-200">
                                <span class="inline-flex items-center gap-1.5">
                                    {{ $inc->typeLabel() }}
                                    @if ($inc->correlated)
                                        <x-nawasara-ui::badge color="danger">Chain</x-nawasara-ui::badge>
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
                            <td class="px-4 py-3 font-mono text-sm text-neutral-700 dark:text-neutral-200">
                                @if($inc->source_ip)
                                    <span class="inline-flex items-center gap-1.5">
                                        <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $inc->source_ip]) }}"
                                           wire:navigate
                                           class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                            {{ $inc->source_ip }}
                                        </a>
                                        {{-- Badge reflects IP state: if this source_ip is blocked at
                                             the edge (via ANY incident), show Blocked here too. --}}
                                        @if(isset($blockedIps[$inc->source_ip]))
                                            <x-nawasara-ui::badge color="danger" title="IP ini sedang di-block di Cloudflare">Blocked</x-nawasara-ui::badge>
                                        @endif
                                    </span>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-600 italic">filesystem</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                                {{ $inc->score }}
                            </td>
                            <td class="px-4 py-3 text-sm">
                                @if ($inc->occurrences > 1)
                                    <x-nawasara-ui::badge color="warning">×{{ number_format($inc->occurrences) }}</x-nawasara-ui::badge>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500">1</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-600 dark:text-neutral-300">
                                @if ($inc->agent)
                                    <a href="{{ route('nawasara-secscan.agents.show', $inc->agent->agent_id) }}"
                                       wire:navigate
                                       class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                        {{ $inc->agent->name }}
                                    </a>
                                    <div class="text-xs text-neutral-400 dark:text-neutral-500">{{ $inc->agent->hostname }}</div>
                                @else
                                    <span class="text-neutral-400">—</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                <span title="{{ $inc->detected_at?->format('d M Y H:i:s') }}">
                                    {{ $inc->detected_at?->diffForHumans() }}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                <span title="{{ ($inc->last_seen_at ?? $inc->detected_at)?->format('d M Y H:i:s') }}">
                                    {{ ($inc->last_seen_at ?? $inc->detected_at)?->diffForHumans() }}
                                </span>
                            </td>
                            <td class="px-4 py-3 text-right">
                                <x-nawasara-ui::dropdown-menu-action :id="$inc->id" :items="[
                                    ['type' => 'click', 'label' => 'Lihat evidence', 'wire:click' => 'openDetail('.$inc->id.')', 'modal' => 'incident-detail-modal', 'icon' => 'lucide-eye'],
                                ]" />
                            </td>
                        </tr>
                    @endforeach
                </x-slot:table>
            </x-nawasara-ui::table>

            <div class="mt-4">
                {{ $incidents->links() }}
            </div>
        @endif
    </x-nawasara-ui::page.card>

    {{-- Incident evidence modal --}}
    <x-nawasara-ui::modal id="incident-detail-modal" title="Detail Insiden">
        @if ($selectedIncident)
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-3 text-sm">
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Tipe</p>
                        <p class="text-neutral-800 dark:text-neutral-100 font-medium">{{ $selectedIncident->typeLabel() }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Severity</p>
                        <x-nawasara-ui::badge :color="$selectedIncident->severityColor()">{{ ucfirst($selectedIncident->severity) }}</x-nawasara-ui::badge>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Source IP</p>
                        <p class="font-mono text-neutral-800 dark:text-neutral-100">{{ $selectedIncident->source_ip ?? '—' }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Score</p>
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
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Agent</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $selectedIncident->agent?->name ?? '—' }}</p>
                    </div>
                    @if ($selectedIncident->mitre_technique)
                        <div class="col-span-2">
                            <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Teknik MITRE ATT&CK</p>
                            <a href="{{ $selectedIncident->mitreUrl() }}" target="_blank" rel="noopener"
                               class="inline-flex items-center gap-1.5 text-sm text-sky-600 dark:text-sky-400 hover:underline">
                                <span class="font-mono font-medium">{{ $selectedIncident->mitre_technique }}</span>
                                <span class="text-neutral-500 dark:text-neutral-400">— {{ $selectedIncident->mitreName() }}</span>
                                <x-lucide-external-link class="size-3.5" />
                            </a>
                        </div>
                    @endif
                </div>

                @if ($selectedIncident->evidence)
                    @php
                        // Distinct target hosts/domains across this incident's evidence
                        // (agent captures the vhost per request, e.g. WHM domlogs).
                        $evHosts = collect($selectedIncident->evidence)
                            ->pluck('host')->filter()->unique()->values();
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
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-2">Evidence</p>
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
                            Insiden ini merupakan bagian dari rantai serangan (group: <span class="font-mono">{{ $selectedIncident->correlated_group_id }}</span>)
                        </p>
                    </div>
                @endif
            </div>

            <x-slot:footer>
                @if($selectedIncident->source_ip)
                    <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $selectedIncident->source_ip]) }}"
                       wire:navigate
                       class="text-sm text-emerald-600 dark:text-emerald-400 hover:underline">
                        Lihat semua insiden dari IP ini →
                    </a>
                @else
                    <span class="text-sm text-neutral-400 dark:text-neutral-600">
                        Tidak ada source IP (filesystem finding)
                    </span>
                @endif
            </x-slot:footer>
        @else
            <x-nawasara-ui::loading />
        @endif
    </x-nawasara-ui::modal>
</div>
