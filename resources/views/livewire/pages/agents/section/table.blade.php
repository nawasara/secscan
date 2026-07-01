<div>
    <div class="flex flex-wrap items-center gap-3 mb-4">
        <x-nawasara-ui::search-input model="search" placeholder="Cari nama, hostname, IP…" />

        <x-nawasara-ui::filter-panel
            :state="['filterStatus' => $filterStatus]"
            :dimensions="['filterStatus' => 'Status']">

            <x-nawasara-ui::filter-group
                label="Status"
                model="filterStatus"
                :items="['online' => 'Online', 'offline' => 'Offline', 'never_connected' => 'Belum Connect']" />

        </x-nawasara-ui::filter-panel>

        <div data-filter-chips></div>
    </div>

    <x-nawasara-ui::page.card>
        @if ($agents->isEmpty())
            <x-nawasara-ui::empty-state
                icon="lucide-shield-off"
                title="Belum ada agent terdaftar"
                description="Install nawasara-agent di server target dan jalankan skrip registrasi." />
        @else
            <x-nawasara-ui::table
                :headers="['Agent', 'Hostname / IP', 'OS', 'Web Server', 'Plugins', 'Health', 'Status', 'Last Seen', 'Incidents', '']"
                stickyLast>
                <x-slot:table>
                    @foreach ($agents as $agent)
                        <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                            <td class="px-4 py-3">
                                <div class="font-medium text-neutral-800 dark:text-neutral-100">
                                    {{ $agent->name }}
                                </div>
                                <div class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">
                                    {{ $agent->agent_id }}
                                </div>
                                @if ($agent->agent_version)
                                    <div class="text-[11px] text-neutral-400 dark:text-neutral-500">v{{ $agent->agent_version }}</div>
                                @endif
                            </td>
                            <td class="px-4 py-3">
                                <div class="font-mono text-sm text-neutral-700 dark:text-neutral-200">
                                    {{ $agent->hostname }}
                                </div>
                                @if ($agent->ip_local)
                                    <div class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">
                                        {{ $agent->ip_local }}
                                    </div>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-600 dark:text-neutral-300">
                                {{ $agent->os ?? '—' }}
                                @if ($agent->arch)
                                    <span class="text-xs text-neutral-400 dark:text-neutral-500">({{ $agent->arch }})</span>
                                @endif
                            </td>
                            <td class="px-4 py-3">
                                @if ($agent->web_server && $agent->web_server !== 'none')
                                    <x-nawasara-ui::badge color="info">{{ $agent->web_server }}</x-nawasara-ui::badge>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500 text-sm">—</span>
                                @endif
                            </td>
                            <td class="px-4 py-3">
                                @if ($agent->plugins_active)
                                    <div class="flex flex-wrap gap-1">
                                        @foreach ($agent->plugins_active as $plugin)
                                            <x-nawasara-ui::badge color="neutral" size="sm">{{ $plugin }}</x-nawasara-ui::badge>
                                        @endforeach
                                    </div>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500 text-sm">—</span>
                                @endif
                            </td>
                            <td class="px-4 py-3">
                                <div class="flex items-center gap-2">
                                    <span class="font-semibold text-sm text-neutral-700 dark:text-neutral-200">
                                        {{ number_format($agent->health_score, 0) }}
                                    </span>
                                    <div class="w-16 h-1.5 bg-neutral-200 dark:bg-neutral-700 rounded-full overflow-hidden">
                                        <div class="h-full rounded-full
                                            @if ($agent->health_score >= 80) bg-emerald-500
                                            @elseif ($agent->health_score >= 60) bg-yellow-500
                                            @else bg-red-500 @endif"
                                            style="width: {{ $agent->health_score }}%"></div>
                                    </div>
                                </div>
                            </td>
                            <td class="px-4 py-3">
                                <x-nawasara-ui::badge :color="$agent->statusColor()">
                                    {{ $agent->statusLabel() }}
                                </x-nawasara-ui::badge>
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-600 dark:text-neutral-300 whitespace-nowrap">
                                @if ($agent->last_seen_at)
                                    <span title="{{ $agent->last_seen_at->format('d M Y H:i:s') }}">
                                        {{ $agent->last_seen_at->diffForHumans() }}
                                    </span>
                                @else
                                    <span class="text-neutral-400 dark:text-neutral-500">Belum pernah</span>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-sm text-neutral-700 dark:text-neutral-200 text-center font-medium">
                                {{ number_format($agent->incidents_count) }}
                            </td>
                            <td class="px-4 py-3">
                                <x-nawasara-ui::icon-button
                                    icon="lucide-external-link"
                                    tooltip="Detail agent"
                                    placement="left"
                                    :href="route('nawasara-secscan.agents.show', $agent->agent_id)"
                                    wire:navigate />
                            </td>
                        </tr>
                    @endforeach
                </x-slot:table>
            </x-nawasara-ui::table>

            <div class="mt-4">
                {{ $agents->links() }}
            </div>
        @endif
    </x-nawasara-ui::page.card>
</div>
