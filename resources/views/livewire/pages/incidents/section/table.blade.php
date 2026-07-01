<div>
    <div class="flex flex-wrap items-center gap-3 mb-4">
        <x-nawasara-ui::search-input model="search" placeholder="Cari IP…" />

        <x-nawasara-ui::filter-panel
            :state="['filterSeverity' => $filterSeverity, 'filterType' => $filterType]"
            :dimensions="['filterSeverity' => 'Severity', 'filterType' => 'Tipe Insiden']">

            <x-nawasara-ui::filter-group
                label="Severity"
                model="filterSeverity"
                :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'info' => 'Info']" />

            <x-nawasara-ui::filter-group
                label="Tipe Insiden"
                model="filterType"
                :items="$typeOptions" />

        </x-nawasara-ui::filter-panel>

        <div data-filter-chips></div>
    </div>

    <x-nawasara-ui::page.card>
        @if ($incidents->isEmpty())
            <x-nawasara-ui::empty-state
                icon="lucide-shield-check"
                variant="celebrate"
                title="Tidak ada insiden"
                description="Belum ada insiden yang dilaporkan oleh agent." />
        @else
            <x-nawasara-ui::table
                :headers="['Severity', 'Tipe', 'Source IP', 'Score', 'Agent', 'Terdeteksi', 'Correlated', '']"
                stickyLast>
                <x-slot:table>
                    @foreach ($incidents as $inc)
                        <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td class="px-4 py-3">
                                <x-nawasara-ui::badge :color="$inc->severityColor()">
                                    {{ ucfirst($inc->severity) }}
                                </x-nawasara-ui::badge>
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-700 dark:text-neutral-200">
                                {{ $inc->typeLabel() }}
                            </td>
                            <td class="px-4 py-3 font-mono text-sm text-neutral-700 dark:text-neutral-200">
                                @if($inc->source_ip)
                                    <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $inc->source_ip]) }}"
                                       wire:navigate
                                       class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                        {{ $inc->source_ip }}
                                    </a>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-600 italic">filesystem</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                                {{ $inc->score }}
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
                            <td class="px-4 py-3">
                                @if ($inc->correlated)
                                    <x-nawasara-ui::badge color="danger">Ya</x-nawasara-ui::badge>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500 text-sm">—</span>
                                @endif
                            </td>
                            <td class="px-4 py-3">
                                <x-nawasara-ui::icon-button
                                    icon="lucide-eye"
                                    tooltip="Lihat evidence"
                                    placement="left"
                                    x-on:click="$dispatch('open-modal', { id: 'incident-detail-modal', loading: true })"
                                    wire:click="openDetail({{ $inc->id }})" />
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
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Terdeteksi</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $selectedIncident->detected_at?->format('d M Y H:i:s') }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Agent</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $selectedIncident->agent?->name ?? '—' }}</p>
                    </div>
                </div>

                @if ($selectedIncident->evidence)
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-2">Evidence</p>
                        <div class="space-y-2">
                            @foreach ($selectedIncident->evidence as $ev)
                                <div class="bg-neutral-50 dark:bg-neutral-900 rounded-lg p-3 text-xs font-mono">
                                    <div class="text-neutral-400 dark:text-neutral-500 mb-1">
                                        {{ $ev['timestamp'] ?? '' }}
                                        @if (!empty($ev['matched_rule']))
                                            · <span class="text-emerald-600 dark:text-emerald-400">{{ $ev['matched_rule'] }}</span>
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
