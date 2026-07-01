<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Agents', 'url' => route('nawasara-secscan.agents')],
                ['label' => $this->agent->name],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            :title="$this->agent->name"
            :description="$this->agent->hostname . ($this->agent->ip_local ? ' · ' . $this->agent->ip_local : '')">
            <x-nawasara-ui::badge :color="$this->agent->statusColor()" size="lg">
                {{ $this->agent->statusLabel() }}
            </x-nawasara-ui::badge>
        </x-nawasara-ui::page-header>

        {{-- Stats bar --}}
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <x-nawasara-ui::stat-card compact
                icon="lucide-activity"
                label="Total Insiden"
                :value="$this->incidentStats['total']"
                color="neutral" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-octagon-alert"
                label="Critical"
                :value="$this->incidentStats['critical']"
                color="danger" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-triangle-alert"
                label="High"
                :value="$this->incidentStats['high']"
                color="warning" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-calendar"
                label="Hari Ini"
                :value="$this->incidentStats['today']"
                color="info" />
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {{-- Left: Agent info + heartbeat --}}
            <div class="space-y-4">

                {{-- Agent info card --}}
                <x-nawasara-ui::page.card>
                    <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-3">Info Agent</p>
                    <dl class="space-y-2 text-sm">
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Versi</dt>
                            <dd class="font-mono text-neutral-800 dark:text-neutral-100">{{ $this->agent->agent_version ?? '—' }}</dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">OS</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $this->agent->os ?? '—' }} {{ $this->agent->arch ? '('.$this->agent->arch.')' : '' }}</dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Web Server</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $this->agent->web_server ?? '—' }}</dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Health Score</dt>
                            <dd>
                                <span class="font-semibold {{ $this->agent->health_score >= 80 ? 'text-emerald-600 dark:text-emerald-400' : ($this->agent->health_score >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400') }}">
                                    {{ number_format($this->agent->health_score, 0) }}
                                </span>
                                <span class="text-neutral-400 dark:text-neutral-500">/100</span>
                            </dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Terdaftar</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $this->agent->registered_at?->format('d M Y') ?? '—' }}</dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Last Seen</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">
                                @if ($this->agent->last_seen_at)
                                    <span title="{{ $this->agent->last_seen_at->format('d M Y H:i:s') }}">
                                        {{ $this->agent->last_seen_at->diffForHumans() }}
                                    </span>
                                @else
                                    <span class="text-neutral-400">Belum pernah</span>
                                @endif
                            </dd>
                        </div>
                        <div class="flex justify-between gap-2">
                            <dt class="text-neutral-500 dark:text-neutral-400 shrink-0">Agent ID</dt>
                            <dd class="font-mono text-xs text-neutral-600 dark:text-neutral-300 break-all">{{ $this->agent->agent_id }}</dd>
                        </div>
                    </dl>

                    @if ($this->agent->plugins_active)
                        <div class="mt-4 pt-4 border-t border-neutral-200 dark:border-neutral-700">
                            <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-2">Plugins Aktif</p>
                            <div class="flex flex-wrap gap-1.5">
                                @foreach ($this->agent->plugins_active as $plugin)
                                    <x-nawasara-ui::badge color="info">{{ $plugin }}</x-nawasara-ui::badge>
                                @endforeach
                            </div>
                        </div>
                    @endif
                </x-nawasara-ui::page.card>

                {{-- Recent heartbeats --}}
                <x-nawasara-ui::page.card>
                    <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-3">Heartbeat Terakhir</p>
                    @forelse ($this->recentHeartbeats as $hb)
                        <div class="flex items-center justify-between gap-2 py-2 border-b border-neutral-100 dark:border-neutral-700/60 last:border-0 text-xs">
                            <div class="text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                {{ $hb->created_at->format('H:i:s') }}
                            </div>
                            <div class="flex items-center gap-3 text-neutral-700 dark:text-neutral-200">
                                <span title="Health Score">
                                    <span class="{{ $hb->health_score >= 80 ? 'text-emerald-600 dark:text-emerald-400' : ($hb->health_score >= 60 ? 'text-yellow-600 dark:text-yellow-400' : 'text-red-600 dark:text-red-400') }} font-semibold">
                                        {{ number_format($hb->health_score, 0) }}
                                    </span>
                                </span>
                                @if ($hb->metrics)
                                    <span title="CPU">CPU {{ number_format($hb->metrics['cpu_percent'] ?? 0, 0) }}%</span>
                                    <span title="RAM">RAM {{ $hb->metrics['mem_used_mb'] ?? 0 }}MB</span>
                                @endif
                                @if ($hb->pending_incidents > 0)
                                    <span class="text-amber-600 dark:text-amber-400" title="Pending incidents">
                                        {{ $hb->pending_incidents }} pending
                                    </span>
                                @endif
                            </div>
                        </div>
                    @empty
                        <p class="text-sm text-neutral-400 dark:text-neutral-500 text-center py-4">Belum ada heartbeat</p>
                    @endforelse
                </x-nawasara-ui::page.card>

            </div>

            {{-- Right: Recent incidents --}}
            <div class="lg:col-span-2">
                <x-nawasara-ui::page.card>
                    <div class="flex items-center justify-between mb-4">
                        <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Insiden Keamanan</p>
                        <div class="flex items-center gap-2">
                            <x-nawasara-ui::filter-panel
                                :state="['filterSeverity' => $filterSeverity]"
                                :dimensions="['filterSeverity' => 'Severity']">
                                <x-nawasara-ui::filter-group
                                    label="Severity"
                                    model="filterSeverity"
                                    :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'info' => 'Info']" />
                            </x-nawasara-ui::filter-panel>
                        </div>
                    </div>

                    <div data-filter-chips class="mb-3"></div>

                    @if ($this->incidents->isEmpty())
                        <x-nawasara-ui::empty-state inline variant="celebrate"
                            icon="lucide-shield-check"
                            title="Tidak ada insiden"
                            description="Belum ada insiden yang tercatat untuk agent ini." />
                    @else
                        <x-nawasara-ui::table
                            :headers="['Severity', 'Tipe', 'Source IP', 'Score', 'Terdeteksi']">
                            <x-slot:table>
                                @foreach ($this->incidents as $inc)
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
                                            <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $inc->source_ip]) }}"
                                               wire:navigate
                                               class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                                {{ $inc->source_ip }}
                                            </a>
                                        </td>
                                        <td class="px-4 py-3 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                                            {{ $inc->score }}
                                        </td>
                                        <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                            <span title="{{ $inc->detected_at?->format('d M Y H:i:s') }}">
                                                {{ $inc->detected_at?->diffForHumans() }}
                                            </span>
                                        </td>
                                    </tr>
                                @endforeach
                            </x-slot:table>
                        </x-nawasara-ui::table>

                        <div class="mt-4">
                            {{ $this->incidents->links() }}
                        </div>
                    @endif
                </x-nawasara-ui::page.card>
            </div>

        </div>
    </x-nawasara-ui::page.container>
</div>
