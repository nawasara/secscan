<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Incidents', 'url' => route('nawasara-secscan.incidents')],
                ['label' => 'IP: ' . $ip],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            :title="'IP: ' . $ip"
            description="Timeline semua insiden keamanan dari sumber IP ini">
            <a href="https://ipinfo.io/{{ $ip }}" target="_blank" rel="noopener noreferrer"
               class="inline-flex items-center gap-1.5 text-sm text-neutral-600 dark:text-neutral-300 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors">
                <x-lucide-external-link class="size-3.5" />
                WhoIs
            </a>
        </x-nawasara-ui::page-header>

        {{-- Summary stats --}}
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
            <x-nawasara-ui::stat-card compact
                icon="lucide-activity"
                label="Total Insiden"
                :value="$this->summary['total']"
                color="neutral" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-octagon-alert"
                label="Critical"
                :value="$this->summary['critical']"
                color="danger" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-triangle-alert"
                label="High"
                :value="$this->summary['high']"
                color="warning" />
            <x-nawasara-ui::stat-card compact
                icon="lucide-server"
                label="VM Terkena"
                :value="$this->summary['agents']"
                color="info" />
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">

            {{-- Left sidebar: meta info --}}
            <div>
                <x-nawasara-ui::page.card>
                    <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-3">Ringkasan</p>
                    <dl class="space-y-3 text-sm">
                        <div>
                            <dt class="text-neutral-500 dark:text-neutral-400 text-xs mb-0.5">Pertama Terdeteksi</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">
                                {{ $this->summary['first_seen'] ? \Carbon\Carbon::parse($this->summary['first_seen'])->format('d M Y H:i') : '—' }}
                            </dd>
                        </div>
                        <div>
                            <dt class="text-neutral-500 dark:text-neutral-400 text-xs mb-0.5">Terakhir Terdeteksi</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">
                                {{ $this->summary['last_seen'] ? \Carbon\Carbon::parse($this->summary['last_seen'])->diffForHumans() : '—' }}
                            </dd>
                        </div>
                        @if ($this->summary['correlated'] > 0)
                            <div>
                                <dt class="text-neutral-500 dark:text-neutral-400 text-xs mb-0.5">Rantai Serangan</dt>
                                <dd>
                                    <x-nawasara-ui::badge color="danger">{{ $this->summary['correlated'] }} correlated</x-nawasara-ui::badge>
                                </dd>
                            </div>
                        @endif
                        @if (count($this->agentNames) > 0)
                            <div>
                                <dt class="text-neutral-500 dark:text-neutral-400 text-xs mb-1">VM yang Diserang</dt>
                                <dd class="space-y-1">
                                    @foreach ($this->agentNames as $agentName)
                                        <div class="text-neutral-700 dark:text-neutral-200 text-xs">{{ $agentName }}</div>
                                    @endforeach
                                </dd>
                            </div>
                        @endif
                    </dl>
                </x-nawasara-ui::page.card>
            </div>

            {{-- Right: Timeline --}}
            <div class="lg:col-span-3">
                <x-nawasara-ui::page.card>
                    <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-4">Timeline Insiden</p>

                    @if ($this->incidents->isEmpty())
                        <x-nawasara-ui::empty-state inline variant="celebrate"
                            icon="lucide-shield-check"
                            title="Tidak ada insiden"
                            description="Tidak ada insiden yang tercatat untuk IP ini." />
                    @else
                        <div class="relative">
                            {{-- Timeline line --}}
                            <div class="absolute left-[1.125rem] top-0 bottom-0 w-px bg-neutral-200 dark:bg-neutral-700"></div>

                            <div class="space-y-4">
                                @foreach ($this->incidents as $inc)
                                    <div class="relative flex gap-4">
                                        {{-- Dot --}}
                                        <div class="relative z-10 shrink-0 flex items-center justify-center w-9 h-9 rounded-full border-2 bg-white dark:bg-neutral-900
                                            @if ($inc->severity === 'critical') border-red-500
                                            @elseif ($inc->severity === 'high') border-orange-400
                                            @elseif ($inc->severity === 'medium') border-blue-400
                                            @else border-neutral-300 dark:border-neutral-600 @endif">
                                            @if ($inc->correlated)
                                                <x-lucide-link-2 class="size-4 @if ($inc->severity === 'critical') text-red-500 @elseif ($inc->severity === 'high') text-orange-400 @else text-blue-400 @endif" />
                                            @else
                                                <x-lucide-shield-alert class="size-4 @if ($inc->severity === 'critical') text-red-500 @elseif ($inc->severity === 'high') text-orange-400 @elseif ($inc->severity === 'medium') text-blue-400 @else text-neutral-400 @endif" />
                                            @endif
                                        </div>

                                        {{-- Content --}}
                                        <div class="flex-1 pb-4">
                                            <div class="flex flex-wrap items-center gap-2 mb-1">
                                                <x-nawasara-ui::badge :color="$inc->severityColor()">{{ ucfirst($inc->severity) }}</x-nawasara-ui::badge>
                                                <span class="font-medium text-sm text-neutral-800 dark:text-neutral-100">{{ $inc->typeLabel() }}</span>
                                                @if ($inc->correlated)
                                                    <x-nawasara-ui::badge color="neutral" size="sm">Correlated</x-nawasara-ui::badge>
                                                @endif
                                            </div>

                                            <div class="flex flex-wrap items-center gap-3 text-xs text-neutral-500 dark:text-neutral-400 mb-2">
                                                <span title="{{ $inc->detected_at?->format('d M Y H:i:s') }}">
                                                    {{ $inc->detected_at?->format('d M Y H:i:s') }}
                                                </span>
                                                @if ($inc->agent)
                                                    <span>·</span>
                                                    <a href="{{ route('nawasara-secscan.agents.show', $inc->agent->agent_id) }}"
                                                       wire:navigate
                                                       class="hover:text-emerald-600 dark:hover:text-emerald-400 hover:underline">
                                                        {{ $inc->agent->name }}
                                                    </a>
                                                @endif
                                                <span>·</span>
                                                <span class="font-semibold text-neutral-700 dark:text-neutral-300">Score: {{ $inc->score }}</span>
                                            </div>

                                            @if ($inc->evidence)
                                                <div class="space-y-1">
                                                    @foreach (array_slice($inc->evidence, 0, 3) as $ev)
                                                        <div class="bg-neutral-50 dark:bg-neutral-900 rounded px-3 py-1.5 font-mono text-xs text-neutral-700 dark:text-neutral-300 break-all">
                                                            {{ $ev['raw'] ?? json_encode($ev) }}
                                                        </div>
                                                    @endforeach
                                                    @if (count($inc->evidence) > 3)
                                                        <p class="text-xs text-neutral-400 dark:text-neutral-500 ps-3">
                                                            +{{ count($inc->evidence) - 3 }} evidence lainnya
                                                        </p>
                                                    @endif
                                                </div>
                                            @endif
                                        </div>
                                    </div>
                                @endforeach
                            </div>
                        </div>
                    @endif
                </x-nawasara-ui::page.card>
            </div>

        </div>
    </x-nawasara-ui::page.container>
</div>
