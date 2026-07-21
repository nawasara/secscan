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
            description="Timeline insiden keamanan dari sumber IP ini">
            <div class="flex flex-wrap items-center gap-3">
                <x-nawasara-ui::time-window
                    :window="$window" :from="$from" :to="$to"
                    :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />
                <a href="https://ipinfo.io/{{ $ip }}" target="_blank" rel="noopener noreferrer"
                   class="inline-flex items-center gap-1.5 text-sm text-neutral-600 dark:text-neutral-300 hover:text-emerald-600 dark:hover:text-emerald-400 transition-colors">
                    <x-lucide-external-link class="size-3.5" />
                    WhoIs
                </a>
            </div>
        </x-nawasara-ui::page-header>

        {{-- Block status — the first thing an analyst needs to know. "dry_run" is
             called out explicitly: the Decision Engine logs a block decision even
             when enforcement is off, and reading that as "handled" would be wrong. --}}
        @php($blk = $this->blockStatus)
        <div class="mb-6">
            @if ($blk['state'] === 'active')
                <div class="flex flex-wrap items-center gap-2 rounded-lg border border-rose-200 dark:border-rose-800/50 bg-rose-50 dark:bg-rose-900/20 px-4 py-3">
                    <x-lucide-shield-ban class="size-4 text-rose-600 dark:text-rose-400 shrink-0" />
                    <span class="text-sm font-medium text-rose-700 dark:text-rose-300">Diblokir di Cloudflare</span>
                    <span class="text-xs text-rose-600/80 dark:text-rose-400/80">
                        sejak {{ $blk['block']->blocked_at?->format('d M Y H:i') }}
                        @if ($blk['block']->reason) &middot; {{ $blk['block']->reason }} @endif
                        &middot; {{ $blk['block']->blocked_by ? 'manual' : 'otomatis' }}
                    </span>
                </div>
            @elseif ($blk['state'] === 'dry_run')
                <div class="flex flex-wrap items-center gap-2 rounded-lg border border-amber-200 dark:border-amber-800/50 bg-amber-50 dark:bg-amber-900/20 px-4 py-3">
                    <x-lucide-triangle-alert class="size-4 text-amber-600 dark:text-amber-400 shrink-0" />
                    <span class="text-sm font-medium text-amber-700 dark:text-amber-300">Diputuskan blok, tapi belum ditegakkan</span>
                    <span class="text-xs text-amber-600/80 dark:text-amber-400/80">
                        mode dry-run &middot; {{ $blk['block']->blocked_at?->format('d M Y H:i') }} &middot; trafik IP ini MASIH masuk
                    </span>
                </div>
            @elseif ($blk['state'] === 'removed')
                <div class="flex flex-wrap items-center gap-2 rounded-lg border border-neutral-200 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-800/50 px-4 py-3">
                    <x-lucide-shield-off class="size-4 text-neutral-500 dark:text-neutral-400 shrink-0" />
                    <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Blokir sudah dicabut</span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400">
                        {{ $blk['block']->unblocked_at?->format('d M Y H:i') }}
                    </span>
                </div>
            @else
                <div class="flex flex-wrap items-center gap-2 rounded-lg border border-neutral-200 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-800/50 px-4 py-3">
                    <x-lucide-shield class="size-4 text-neutral-500 dark:text-neutral-400 shrink-0" />
                    <span class="text-sm font-medium text-neutral-700 dark:text-neutral-200">Tidak diblokir</span>
                    <span class="text-xs text-neutral-500 dark:text-neutral-400">IP ini tidak ada di daftar blokir Cloudflare</span>
                </div>
            @endif
        </div>

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
                        @if ($this->geo)
                            <div>
                                <dt class="text-neutral-500 dark:text-neutral-400 text-xs mb-0.5">Lokasi</dt>
                                <dd class="text-neutral-800 dark:text-neutral-100">
                                    @if ($this->geo['is_private'])
                                        <span class="text-sky-600 dark:text-sky-400">{{ $this->geo['country'] }}</span>
                                    @else
                                        {{ collect([$this->geo['city'], $this->geo['country']])->filter()->implode(', ') ?: '—' }}
                                    @endif
                                </dd>
                                @if ($this->geo['org'])
                                    <dd class="text-neutral-500 dark:text-neutral-400 text-xs mt-0.5">
                                        {{ $this->geo['org'] }}
                                    </dd>
                                @endif
                            </div>
                        @endif
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
                                    @php
                                        // Precompute severity colour classes. Inline @if inside a
                                        // lucide component attribute compiles to a PHP if-block that
                                        // breaks the SVG component's attribute parser, so resolve here.
                                        $dotBorder = match ($inc->severity) {
                                            'critical' => 'border-red-500',
                                            'high' => 'border-orange-400',
                                            'medium' => 'border-blue-400',
                                            default => 'border-neutral-300 dark:border-neutral-600',
                                        };
                                        $dotIconColor = match ($inc->severity) {
                                            'critical' => 'text-red-500',
                                            'high' => 'text-orange-400',
                                            'medium' => 'text-blue-400',
                                            default => 'text-neutral-400',
                                        };
                                    @endphp
                                    <div class="relative flex gap-4">
                                        {{-- Dot --}}
                                        <div class="relative z-10 shrink-0 flex items-center justify-center w-9 h-9 rounded-full border-2 bg-white dark:bg-neutral-900 {{ $dotBorder }}">
                                            @if ($inc->correlated)
                                                <x-lucide-link-2 class="size-4 {{ $dotIconColor }}" />
                                            @else
                                                <x-lucide-shield-alert class="size-4 {{ $dotIconColor }}" />
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

                                            @php
                                                $incHosts = collect($inc->evidence ?? [])->pluck('host')->filter()->unique()->values();
                                            @endphp
                                            @if ($incHosts->isNotEmpty())
                                                <div class="flex flex-wrap gap-1.5 mb-1.5">
                                                    @foreach ($incHosts as $h)
                                                        <span class="inline-flex items-center gap-1 rounded bg-amber-50 dark:bg-amber-900/30 px-2 py-0.5 text-xs font-mono text-amber-700 dark:text-amber-300">
                                                            <x-lucide-globe class="size-3" />{{ $h }}
                                                        </span>
                                                    @endforeach
                                                </div>
                                            @endif

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
