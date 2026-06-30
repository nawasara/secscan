<div>
    <x-nawasara-ui::page.card>
        <div class="flex flex-col md:flex-row gap-3 mb-4">
            <x-nawasara-ui::search-input model="search" placeholder="Cari IP…" />

            <select wire:model.live="filterSeverity"
                class="rounded-lg border border-neutral-300 dark:border-neutral-600 bg-white dark:bg-neutral-800 text-sm text-neutral-700 dark:text-neutral-200 px-3 py-2 min-w-[140px]">
                <option value="">Semua Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="info">Info</option>
            </select>

            <select wire:model.live="filterType"
                class="rounded-lg border border-neutral-300 dark:border-neutral-600 bg-white dark:bg-neutral-800 text-sm text-neutral-700 dark:text-neutral-200 px-3 py-2 min-w-[180px]">
                <option value="">Semua Tipe</option>
                @foreach ($typeOptions as $val => $label)
                    <option value="{{ $val }}">{{ $label }}</option>
                @endforeach
            </select>
        </div>

        @if ($incidents->isEmpty())
            <x-nawasara-ui::empty-state
                icon="shield-check"
                variant="celebrate"
                title="Tidak ada insiden"
                description="Belum ada insiden yang dilaporkan oleh agent." />
        @else
            <x-nawasara-ui::table
                :headers="['Severity', 'Tipe', 'Source IP', 'Score', 'Agent', 'Terdeteksi', 'Correlated']"
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
                                {{ $inc->source_ip }}
                            </td>
                            <td class="px-4 py-3 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                                {{ $inc->score }}
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-600 dark:text-neutral-300">
                                @if ($inc->agent)
                                    <div>{{ $inc->agent->name }}</div>
                                    <div class="text-xs text-neutral-400 dark:text-neutral-500">{{ $inc->agent->hostname }}</div>
                                @else
                                    <span class="text-neutral-400">—</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                {{ $inc->detected_at?->diffForHumans() }}
                            </td>
                            <td class="px-4 py-3">
                                @if ($inc->correlated)
                                    <x-nawasara-ui::badge color="danger">Ya</x-nawasara-ui::badge>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500 text-sm">—</span>
                                @endif
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
</div>
