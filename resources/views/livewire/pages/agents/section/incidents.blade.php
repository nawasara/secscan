<div>
    <div class="flex items-center justify-between mb-4">
        <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Insiden Keamanan</p>
        <div class="flex flex-wrap items-center gap-2">
            <x-nawasara-ui::filter-panel
                label="Filter"
                :state="['filterSeverity' => $filterSeverity]"
                :dimensions="['filterSeverity' => 'Severity']">
                <x-nawasara-ui::filter-group
                    label="Severity"
                    model="filterSeverity"
                    :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'info' => 'Info']"
                    icon="lucide-octagon-alert" />
            </x-nawasara-ui::filter-panel>

            <x-nawasara-ui::time-window
                :window="$window" :from="$from" :to="$to"
                :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />

            <x-nawasara-ui::export-button
                permission="secscan.export"
                tooltip="Ekspor insiden agent (maks 10.000 baris)" />
        </div>
    </div>

    <div wire:ignore data-filter-chips class="mb-3"></div>

    @if ($incidents->isEmpty())
        <x-nawasara-ui::empty-state inline variant="celebrate"
            icon="lucide-shield-check"
            title="Tidak ada insiden"
            description="Belum ada insiden yang tercatat untuk agent ini." />
    @else
        <x-nawasara-ui::table
            :headers="['Severity', 'Tipe', 'Source IP', 'Score', 'Kejadian', 'Terakhir']">
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
                        <td class="px-4 py-3 text-sm">
                            @if ($inc->occurrences > 1)
                                <x-nawasara-ui::badge color="warning">×{{ number_format($inc->occurrences) }}</x-nawasara-ui::badge>
                            @else
                                <span class="text-neutral-400 dark:text-neutral-500">1</span>
                            @endif
                        </td>
                        <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            <span title="{{ ($inc->last_seen_at ?? $inc->detected_at)?->format('d M Y H:i:s') }}">
                                {{ ($inc->last_seen_at ?? $inc->detected_at)?->diffForHumans() }}
                            </span>
                        </td>
                    </tr>
                @endforeach
            </x-slot:table>
        </x-nawasara-ui::table>

        <div class="mt-4">
            {{ $incidents->links() }}
        </div>
    @endif
</div>
