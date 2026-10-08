<div>
    <div class="space-y-2 mb-4">
        <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
            <div class="flex flex-wrap items-center gap-2 shrink-0">
                <x-nawasara-ui::filter-panel
                    label="Filter"
                    :state="['filterStatus' => $filterStatus]"
                    :labels="['filterStatus' => ['online' => 'Online', 'offline' => 'Offline', 'never_connected' => 'Belum terhubung']]"
                    :dimensions="['filterStatus' => 'Status']">
                    <x-nawasara-ui::filter-group
                        label="Status"
                        model="filterStatus"
                        :items="['online' => 'Online', 'offline' => 'Offline', 'never_connected' => 'Belum terhubung']"
                        icon="lucide-activity" />
                </x-nawasara-ui::filter-panel>
            </div>

            <x-nawasara-ui::search-input model="search" placeholder="Cari nama, hostname, IP..." />

            <x-nawasara-ui::export-button
                permission="secscan.export"
                tooltip="Ekspor daftar agen sesuai saringan" />
        </div>

        <div wire:ignore data-filter-chips></div>

        @if ($search !== '')
            <div class="flex flex-wrap items-center gap-2">
                <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
            </div>
        @endif
    </div>

    {{-- OS, web server, dan plugin digabung dalam satu kolom Sistem: sepuluh
         kolom membuat tabel menggulir ke samping di layar laptop. --}}
    <x-nawasara-ui::table
        :headers="['Agen', 'Host / IP', 'Sistem', 'Health', 'Status', 'Terakhir lapor', 'Insiden', '']"
        stickyLast>
        <x-slot:table>
            @forelse ($agents as $agent)
                @php
                    $items = [
                        ['type' => 'link', 'label' => 'Detail agen', 'href' => route('nawasara-secscan.agents.show', $agent->agent_id),
                         'navigate' => true, 'icon' => 'lucide-external-link'],
                        ['type' => 'click', 'label' => 'Cabut agen', 'wire:click' => 'revoke('.$agent->id.')',
                         'icon' => 'lucide-unplug', 'permission' => 'secscan.agent.delete',
                         'confirm' => 'Cabut agen '.$agent->name.'? Kuncinya berhenti berlaku dan perintah yang tertahan dibatalkan. Riwayat insidennya tetap tersimpan.'],
                    ];
                @endphp
                <tr wire:key="agent-{{ $agent->id }}" class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                    <td class="px-6 py-4">
                        <a href="{{ route('nawasara-secscan.agents.show', $agent->agent_id) }}"
                           wire:navigate
                           class="font-medium text-neutral-800 dark:text-neutral-100 hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                            {{ $agent->name }}
                        </a>
                        <div class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">{{ $agent->agent_id }}</div>
                        @if ($agent->versionLabel())
                            <div class="text-[11px] text-neutral-400 dark:text-neutral-500">{{ $agent->versionLabel() }}</div>
                        @endif
                    </td>
                    <td class="px-6 py-4">
                        <div class="font-mono text-sm text-neutral-700 dark:text-neutral-200">{{ $agent->hostname }}</div>
                        @if ($agent->ip_local)
                            <div class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">{{ $agent->ip_local }}</div>
                        @endif
                    </td>
                    <td class="px-6 py-4">
                        <div class="text-sm text-neutral-600 dark:text-neutral-300">
                            {{ $agent->os ?? '-' }}
                            @if ($agent->arch)
                                <span class="text-xs text-neutral-400 dark:text-neutral-500">({{ $agent->arch }})</span>
                            @endif
                        </div>
                        <div class="mt-1 flex flex-wrap gap-1">
                            @if ($agent->web_server && $agent->web_server !== 'none')
                                <x-nawasara-ui::badge color="info" size="sm">{{ $agent->web_server }}</x-nawasara-ui::badge>
                            @endif
                            @foreach ((array) $agent->plugins_active as $plugin)
                                <x-nawasara-ui::badge color="neutral" size="sm">{{ $plugin }}</x-nawasara-ui::badge>
                            @endforeach
                        </div>
                    </td>
                    <td class="px-6 py-4">
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
                    <td class="px-6 py-4">
                        <x-nawasara-ui::badge :color="$agent->statusColor()">{{ $agent->statusLabel() }}</x-nawasara-ui::badge>
                        @if ($agent->stuck_commands_count > 0)
                            <div class="mt-1 text-xs text-amber-600 dark:text-amber-400 whitespace-nowrap"
                                title="Perintah blokir yang sudah disetujui tetapi belum diambil agen">
                                {{ number_format($agent->stuck_commands_count) }} perintah tertahan
                            </div>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-600 dark:text-neutral-300 whitespace-nowrap">
                        @if ($agent->last_seen_at)
                            <span title="{{ $agent->last_seen_at->format('d M Y H:i:s') }}">{{ $agent->last_seen_at->diffForHumans() }}</span>
                        @else
                            <span class="text-neutral-400 dark:text-neutral-500">Belum pernah</span>
                        @endif
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-700 dark:text-neutral-200 text-center font-medium">
                        {{ number_format($agent->incidents_count) }}
                    </td>
                    <td class="px-6 py-4 text-right">
                        <x-nawasara-ui::dropdown-menu-action :id="$agent->id" :items="$items" />
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="8" class="px-6 py-6">
                        @if ($search !== '' || $filterStatus !== '')
                            <x-nawasara-ui::empty-state inline icon="lucide-search-x"
                                title="Tidak ada yang cocok" description="Ubah kata kunci atau saringannya." />
                        @else
                            <x-nawasara-ui::empty-state inline icon="lucide-shield-off"
                                title="Belum ada agen terdaftar"
                                description="Pasang nawasara-agent di server target dan jalankan skrip registrasi." />
                        @endif
                    </td>
                </tr>
            @endforelse
        </x-slot:table>
    </x-nawasara-ui::table>

    <div class="mt-4">
        {{ $agents->links() }}
    </div>
</div>
