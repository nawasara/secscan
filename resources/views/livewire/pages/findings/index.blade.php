<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Keamanan', 'url' => '#'], ['label' => 'Temuan']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Temuan Keamanan"
            description="Indikasi situs ter-retas / judi online / malware dari pemindaian database, probe HTTP, dan laporan agent."
            :count="($tab === 'incidents' ? $this->incidents->total() . ' incidents' : $this->rows->total() . ' temuan')" />

        {{-- Tab switcher --}}
        <div class="flex gap-1 mb-5 border-b border-neutral-200 dark:border-neutral-700">
            <button wire:click="$set('tab','findings')"
                class="px-4 py-2 text-sm font-medium border-b-2 transition-colors
                    {{ $tab === 'findings'
                        ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
                        : 'border-transparent text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200' }}">
                Temuan Website
            </button>
            <button wire:click="$set('tab','incidents')"
                class="px-4 py-2 text-sm font-medium border-b-2 transition-colors
                    {{ $tab === 'incidents'
                        ? 'border-emerald-500 text-emerald-600 dark:text-emerald-400'
                        : 'border-transparent text-neutral-500 dark:text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200' }}">
                Incidents Agent
            </button>
        </div>

        @if ($tab === 'findings')
        @php
            $severityLabels = ['critical' => 'Kritis', 'warning' => 'Peringatan', 'info' => 'Info'];
            $statusLabels = \Nawasara\Secscan\Models\SecscanFinding::statusLabels();
            $threatLabels = $this->threatOptions;
            $sourceLabels = ['sql' => 'SQL (DB)', 'http' => 'HTTP (Probe)'];
        @endphp

        {{-- Toolbar: satu filter-panel (severity/status/threat/source semua multi-select) --}}
        <div class="space-y-2 mb-4">
            <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
                <div class="flex flex-wrap items-center gap-2 shrink-0">
                    <x-nawasara-ui::filter-panel label="Filter" :state="[
                        'severityFilter' => $severityFilter,
                        'statusFilter' => $statusFilter,
                        'threatFilter' => $threatFilter,
                        'sourceFilter' => $sourceFilter,
                    ]" :multiple="['severityFilter', 'statusFilter', 'threatFilter', 'sourceFilter']" :labels="[
                        'severityFilter' => $severityLabels,
                        'statusFilter' => $statusLabels,
                        'threatFilter' => $threatLabels,
                        'sourceFilter' => $sourceLabels,
                    ]" :dimensions="[
                        'severityFilter' => 'Severity',
                        'statusFilter' => 'Status',
                        'threatFilter' => 'Jenis Ancaman',
                        'sourceFilter' => 'Sumber',
                    ]">
                        <x-nawasara-ui::filter-group label="Severity" model="severityFilter" :items="$severityLabels"
                            icon="lucide-octagon-alert" />
                        <x-nawasara-ui::filter-group label="Status" model="statusFilter" :items="$statusLabels"
                            icon="lucide-list-checks" />
                        <x-nawasara-ui::filter-group label="Jenis Ancaman" model="threatFilter" :items="$threatLabels"
                            icon="lucide-bug" />
                        <x-nawasara-ui::filter-group label="Sumber" model="sourceFilter" :items="$sourceLabels"
                            icon="lucide-scan" />
                    </x-nawasara-ui::filter-panel>
                </div>

                <x-nawasara-ui::search-input model="search" placeholder="Cari situs, database, URL..." />
            </div>

            <div wire:ignore data-filter-chips></div>

            @if ($search !== '')
                <div class="flex flex-wrap items-center gap-2">
                    <x-nawasara-ui::filter-chip label="Cari: {{ $search }}" model="search" />
                </div>
            @endif
        </div>

        {{-- Table --}}
        <x-nawasara-ui::table stickyLast :headers="['Severity', 'Situs', 'Jenis', 'Skor', 'Sumber', 'Status', 'Terakhir', '']">
            <x-slot:table>
                @forelse ($this->rows as $finding)
                    <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-700/40">
                        <td class="px-4 py-2.5">
                            <x-nawasara-ui::badge :color="$finding->severityColor()">
                                {{ $severityLabels[$finding->severity] ?? ucfirst($finding->severity) }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-2.5">
                            <div class="text-sm font-medium text-neutral-800 dark:text-neutral-100 truncate max-w-[240px]">
                                {{ $finding->displayName() }}
                            </div>
                            <div class="text-xs text-neutral-400 dark:text-neutral-500 truncate max-w-[240px]">
                                @if ($finding->isHttpSource() && $finding->scan_path && $finding->scan_path !== '/')
                                    {{ $finding->db_name }}{{ $finding->scan_path }}
                                @elseif ($finding->site_url)
                                    {{ $finding->db_name }} · {{ $finding->site_url }}
                                @else
                                    {{ $finding->db_name }}
                                @endif
                            </div>
                        </td>
                        <td class="px-4 py-2.5 text-sm text-neutral-600 dark:text-neutral-300">
                            {{ $finding->threatLabel() }}
                        </td>
                        <td class="px-4 py-2.5 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                            {{ $finding->score }}
                        </td>
                        <td class="px-4 py-2.5">
                            <x-nawasara-ui::badge :color="$finding->sourceColor()">{{ $finding->sourceLabel() }}</x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-2.5">
                            <x-nawasara-ui::badge :color="$finding->statusColor()">{{ $finding->statusLabel() }}</x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-2.5 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            {{ $finding->last_detected_at?->diffForHumans() ?? '—' }}
                        </td>
                        <td class="px-4 py-2.5 text-right">
                            <x-nawasara-ui::icon-button icon="eye" tooltip="Detail & tindak lanjut" placement="left"
                                wire:click="openDetail({{ $finding->id }})" />
                        </td>
                    </tr>
                @empty
                    <tr>
                        <td colspan="8" class="px-4 py-6">
                            <x-nawasara-ui::empty-state inline variant="celebrate" icon="lucide-shield-check"
                                title="Tidak ada temuan" description="Tidak ada indikator yang cocok dengan filter saat ini." />
                        </td>
                    </tr>
                @endforelse
            </x-slot:table>
        </x-nawasara-ui::table>

        <div class="mt-4">
            {{ $this->rows->links() }}
        </div>

        {{-- Detail + triage modal --}}
        <x-nawasara-ui::modal id="secscan-finding-detail" title="Detail Temuan" maxWidth="2xl">
            @if ($this->detail)
                @php $d = $this->detail; @endphp
                <div class="space-y-4">
                    <div class="flex items-center gap-2 flex-wrap">
                        <x-nawasara-ui::badge :color="$d->severityColor()">{{ ucfirst($d->severity) }}</x-nawasara-ui::badge>
                        <x-nawasara-ui::badge :color="$d->statusColor()">{{ $d->statusLabel() }}</x-nawasara-ui::badge>
                        <x-nawasara-ui::badge :color="$d->sourceColor()">{{ $d->sourceLabel() }}</x-nawasara-ui::badge>
                        <span class="text-sm font-semibold text-neutral-700 dark:text-neutral-200">Skor {{ $d->score }}</span>
                    </div>

                    <dl class="grid grid-cols-2 gap-3 text-sm">
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">Situs</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->displayName() }}</dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">{{ $d->isHttpSource() ? 'Hostname' : 'Database' }}</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->db_name }}</dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">URL</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100 break-all">
                                @if ($d->displayUrl())
                                    <a href="{{ $d->displayUrl() }}" target="_blank" rel="noopener noreferrer"
                                        class="text-emerald-600 dark:text-emerald-400 hover:underline">
                                        {{ $d->displayUrl() }}
                                    </a>
                                @else
                                    —
                                @endif
                            </dd>
                        </div>
                        <div>
                            <dt class="text-xs text-neutral-500 dark:text-neutral-400">Jenis</dt>
                            <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->threatLabel() }}</dd>
                        </div>
                        @if ($d->isHttpSource() && $d->scan_path)
                            <div>
                                <dt class="text-xs text-neutral-500 dark:text-neutral-400">Path Dipindai</dt>
                                <dd class="text-neutral-800 dark:text-neutral-100 font-mono text-xs">{{ $d->scan_path }}</dd>
                            </div>
                        @endif
                    </dl>

                    {{-- Evidence --}}
                    @php $ev = $d->evidence ?? []; @endphp
                    <div>
                        <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-2">Bukti</p>

                        {{-- Judol post links: clickable ?p=ID to the live page --}}
                        @if (! empty($ev['samples']))
                            <div class="mb-3">
                                <p class="text-xs text-neutral-600 dark:text-neutral-300 mb-1">
                                    {{ $ev['published_judol_posts'] ?? count($ev['samples']) }} postingan judi online terbit
                                    @if (($ev['published_judol_posts'] ?? 0) > count($ev['samples']))
                                        <span class="text-neutral-400">(menampilkan {{ count($ev['samples']) }} contoh)</span>
                                    @endif
                                </p>
                                <ul class="space-y-1.5">
                                    @foreach ($ev['samples'] as $s)
                                        <li class="text-sm">
                                            <div class="text-neutral-800 dark:text-neutral-100 truncate">{{ $s['title'] ?? '—' }}</div>
                                            @if (! empty($s['url']))
                                                <a href="{{ $s['url'] }}" target="_blank" rel="noopener noreferrer"
                                                    class="inline-flex items-center gap-1 text-xs text-emerald-600 dark:text-emerald-400 hover:underline break-all">
                                                    <x-lucide-external-link class="size-3 shrink-0" />
                                                    {{ $s['url'] }}
                                                </a>
                                            @endif
                                        </li>
                                    @endforeach
                                </ul>
                            </div>
                        @endif

                        {{-- Other signals as readable lines --}}
                        @php
                            $otherKeys = [
                                // SQL-source F1 signals
                                'injected_posts' => 'Postingan dengan konten ter-inject',
                                'suspicious_autoload_options' => 'Opsi autoload mencurigakan',
                                'offsite_urls' => 'URL mengarah ke luar domain resmi',
                                'recently_registered_admins' => 'Admin baru terdaftar (≤14 hari)',
                                'admin_count' => 'Jumlah admin',
                                'blogname' => 'Nama situs (blogname)',
                                // HTTP-source F2 signals
                                'title' => 'Judul halaman terdeteksi',
                                'title_strong_keywords' => 'Kata kunci judol kuat di judul',
                                'title_weak_keywords' => 'Kata kunci judol lemah di judul',
                                'meta_description' => 'Meta description terdeteksi',
                                'meta_description_keywords' => 'Kata kunci di meta description',
                                'body_strong_keyword_density' => 'Kepadatan kata kunci judol di body',
                                'deface_title_pattern' => 'Pola defacement di judul',
                                'deface_body_pattern' => 'Pola defacement di body',
                                'meta_redirect' => 'Meta refresh redirect off-domain',
                                'js_redirect' => 'JS redirect off-domain',
                                'redirect_target' => 'Target redirect',
                                'hidden_div_keywords' => 'Kata kunci tersembunyi (display:none)',
                                'hidden_snippet' => 'Konten tersembunyi (cuplikan)',
                                'external_iframes' => 'Iframe eksternal',
                                'gambling_outbound_domains' => 'Domain judi di outbound link',
                                'gambling_link_count' => 'Jumlah link ke domain judi',
                                'total_external_domains' => 'Total domain eksternal unik',
                                'foreign_script_title' => 'Judul menggunakan aksara asing',
                                'cloaking_detected' => 'Cloaking terdeteksi (konten beda UA)',
                                'note' => 'Catatan',
                            ];
                        @endphp
                        @foreach ($otherKeys as $k => $label)
                            @if (isset($ev[$k]) && $ev[$k] !== [] && $ev[$k] !== '')
                                <div class="text-xs text-neutral-600 dark:text-neutral-300 mb-0.5">
                                    <span class="text-neutral-400 dark:text-neutral-500">{{ $label }}:</span>
                                    {{ is_array($ev[$k]) ? json_encode($ev[$k], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : $ev[$k] }}
                                </div>
                            @endif
                        @endforeach

                        {{-- Raw evidence (collapsible, for completeness) --}}
                        <details class="mt-2">
                            <summary class="text-xs text-neutral-400 dark:text-neutral-500 cursor-pointer hover:text-neutral-600 dark:hover:text-neutral-300">Data mentah</summary>
                            <pre class="text-xs bg-gray-50 dark:bg-neutral-900 border border-gray-200 dark:border-neutral-700 rounded-lg p-3 overflow-x-auto text-neutral-700 dark:text-neutral-300 mt-1">{{ json_encode($ev, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) }}</pre>
                        </details>
                    </div>

                    {{-- History --}}
                    @if ($d->histories->isNotEmpty())
                        <div>
                            <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400 mb-1">Riwayat</p>
                            <ul class="space-y-1 text-xs text-neutral-600 dark:text-neutral-400">
                                @foreach ($d->histories->sortByDesc('created_at') as $h)
                                    <li>
                                        <span class="text-neutral-400">{{ $h->created_at?->diffForHumans() }}</span>
                                        — {{ $h->status_from ?? 'baru' }} → <strong>{{ $h->status_to }}</strong>
                                        @if ($h->reason) · {{ $h->reason }} @endif
                                    </li>
                                @endforeach
                            </ul>
                        </div>
                    @endif

                    @can('secscan.finding.triage')
                        @if ($d->isActive())
                            <div class="border-t border-gray-200 dark:border-neutral-700 pt-3 space-y-2">
                                <x-nawasara-ui::form.textarea wire:model="triageReason" label="Catatan (opsional)" :rows="2"
                                    placeholder="Alasan / tindak lanjut..." />
                            </div>
                        @endif
                    @endcan
                </div>

                <x-slot:footer>
                    @can('secscan.finding.triage')
                        @if ($d->isActive())
                            @if ($d->status === \Nawasara\Secscan\Models\SecscanFinding::STATUS_OPEN)
                                <x-nawasara-ui::button color="warning" variant="outline" wire:click="acknowledge({{ $d->id }})">
                                    Akui
                                </x-nawasara-ui::button>
                            @endif
                            <x-nawasara-ui::button color="neutral" variant="outline" wire:click="markFalsePositive({{ $d->id }})">
                                False Positive
                            </x-nawasara-ui::button>
                            <x-nawasara-ui::button color="success" wire:click="resolve({{ $d->id }})">
                                Tandai Selesai
                            </x-nawasara-ui::button>
                        @endif
                    @endcan
                </x-slot:footer>
            @endif
        </x-nawasara-ui::modal>

        @elseif ($tab === 'incidents')

        {{-- Incidents Agent tab --}}
        <x-nawasara-ui::page.card>
            {{-- Toolbar: search di kiri, filter-panel di kanan. --}}
            <div class="space-y-2 mb-4">
                <div class="flex flex-col md:flex-row md:flex-nowrap md:items-center gap-2">
                    <x-nawasara-ui::search-input model="incSearch" placeholder="Cari IP sumber…" />

                    <div class="flex flex-wrap items-center gap-2 shrink-0">
                        <x-nawasara-ui::filter-panel
                            label="Filter"
                            :state="['incSeverity' => $incSeverity, 'incType' => $incType]"
                            :dimensions="['incSeverity' => 'Severity', 'incType' => 'Tipe Insiden']">

                            <x-nawasara-ui::filter-group
                                label="Severity"
                                model="incSeverity"
                                :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium', 'info' => 'Info']"
                                icon="lucide-circle-check" />

                            <x-nawasara-ui::filter-group
                                label="Tipe Insiden"
                                model="incType"
                                :items="$this->incidentTypeOptions"
                                icon="lucide-shield-alert" />

                        </x-nawasara-ui::filter-panel>
                    </div>
                </div>

                <div wire:ignore data-filter-chips></div>
            </div>

            @if ($this->incidents->isEmpty())
                <x-nawasara-ui::empty-state
                    icon="lucide-shield-check"
                    variant="celebrate"
                    title="Tidak ada incidents"
                    description="Belum ada insiden yang dilaporkan oleh nawasara-agent." />
            @else
                <x-nawasara-ui::table stickyLast
                    :headers="['Severity', 'Tipe', 'Source IP', 'Skor', 'Agent', 'Terdeteksi', 'Correlated', '']">
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
                                    @if ($inc->source_ip)
                                        {{ $inc->source_ip }}
                                    @else
                                        <span class="text-neutral-400 dark:text-neutral-600 italic">filesystem</span>
                                    @endif
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
                                <td class="px-4 py-3 text-right">
                                    <x-nawasara-ui::dropdown-menu-action :id="$inc->id" :items="[
                                        ['type' => 'click', 'label' => 'Lihat evidence', 'wire:click' => 'openIncidentDetail('.$inc->id.')', 'modal' => 'secscan-incident-detail', 'icon' => 'lucide-eye'],
                                    ]" />
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

        @endif

    </x-nawasara-ui::page.container>

    {{-- Incident evidence modal (Incidents Agent tab) --}}
    <x-nawasara-ui::modal id="secscan-incident-detail" title="Detail Insiden">
        @if ($this->incidentDetail)
            @php($inc = $this->incidentDetail)
            <div class="space-y-4">
                <div class="grid grid-cols-2 gap-3 text-sm">
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Tipe</p>
                        <p class="text-neutral-800 dark:text-neutral-100 font-medium">{{ $inc->typeLabel() }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Severity</p>
                        <x-nawasara-ui::badge :color="$inc->severityColor()">{{ ucfirst($inc->severity) }}</x-nawasara-ui::badge>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Source IP</p>
                        <p class="font-mono text-neutral-800 dark:text-neutral-100">{{ $inc->source_ip ?? '—' }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Skor</p>
                        <p class="font-semibold text-neutral-800 dark:text-neutral-100">{{ $inc->score }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Terdeteksi</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $inc->detected_at?->format('d M Y H:i:s') }}</p>
                    </div>
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-1">Agent</p>
                        <p class="text-neutral-700 dark:text-neutral-200">{{ $inc->agent?->name ?? '—' }}</p>
                    </div>
                </div>

                @if ($inc->evidence)
                    <div>
                        <p class="text-xs font-medium text-neutral-500 dark:text-neutral-400 uppercase tracking-wide mb-2">Evidence</p>
                        <div class="space-y-2">
                            @foreach ($inc->evidence as $ev)
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

                @if ($inc->correlated && $inc->correlated_group_id)
                    <div class="flex items-center gap-2 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800/50">
                        <x-lucide-link-2 class="size-4 text-red-600 dark:text-red-400 shrink-0" />
                        <p class="text-xs text-red-700 dark:text-red-300">
                            Insiden ini merupakan bagian dari rantai serangan (group: <span class="font-mono">{{ $inc->correlated_group_id }}</span>)
                        </p>
                    </div>
                @endif
            </div>

            <x-slot:footer>
                @if ($inc->source_ip)
                    <a href="{{ route('nawasara-secscan.ip-timeline', ['ip' => $inc->source_ip]) }}"
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
