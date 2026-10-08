<div>
    <x-nawasara-ui::page-header
        title="Temuan Website"
        description="Indikasi situs ter-retas / judi online / malware dari pemindaian database dan probe HTTP."
        :count="$this->rows->total() . ' temuan'">
        <x-nawasara-ui::time-window
            :window="$window" :from="$from" :to="$to"
            :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />
        <x-nawasara-ui::export-button
            permission="secscan.export"
            tooltip="Ekspor temuan sesuai saringan (maks 10.000 baris)" />
    </x-nawasara-ui::page-header>

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
                    <x-nawasara-ui::filter-group label="Status" model="statusFilter" :items="$statusLabels"
                        icon="lucide-list-checks" />
                    <x-nawasara-ui::filter-group label="Severity" model="severityFilter" :items="$severityLabels"
                        icon="lucide-octagon-alert" />
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

    {{-- Sumber (SQL/HTTP) ikut di baris kedua kolom Situs, bukan kolom sendiri:
         delapan kolom membuat tabel menggulir ke samping di layar laptop, dan
         yang terpotong justru nama situsnya. --}}
    <x-nawasara-ui::table stickyLast :headers="['Severity', 'Situs', 'Jenis', 'Skor', 'Status', 'Terakhir', '']">
        <x-slot:table>
            @forelse ($this->rows as $finding)
                @php
                    $canTriage = $finding->isActive();
                    $items = [
                        ['type' => 'click', 'label' => 'Detail', 'wire:click' => 'openDetail('.$finding->id.')',
                         'modal' => 'secscan-finding-detail', 'icon' => 'lucide-eye'],
                    ];
                    if ($finding->status === \Nawasara\Secscan\Models\SecscanFinding::STATUS_OPEN) {
                        $items[] = ['type' => 'click', 'label' => 'Akui (sedang ditangani)', 'wire:click' => 'acknowledge('.$finding->id.')',
                            'icon' => 'lucide-hand', 'permission' => 'secscan.finding.triage'];
                    }
                    if ($canTriage) {
                        $items[] = ['type' => 'click', 'label' => 'Tandai Selesai', 'wire:click' => 'resolve('.$finding->id.')',
                            'icon' => 'lucide-circle-check', 'permission' => 'secscan.finding.triage',
                            'confirm' => 'Tandai temuan ini selesai? Bila pemindai masih mendeteksinya, temuan akan terbuka lagi.'];
                        $items[] = ['type' => 'click', 'label' => 'False Positive', 'wire:click' => 'markFalsePositive('.$finding->id.')',
                            'icon' => 'lucide-ban', 'permission' => 'secscan.finding.triage',
                            'confirm' => 'Tandai sebagai false positive? Pemindai tidak akan membuka temuan ini lagi.'];
                    }
                @endphp
                <tr wire:key="finding-{{ $finding->id }}" class="hover:bg-neutral-50 dark:hover:bg-neutral-700/40">
                    <td class="px-6 py-4">
                        <x-nawasara-ui::badge :color="$finding->severityColor()">
                            {{ $severityLabels[$finding->severity] ?? ucfirst($finding->severity) }}
                        </x-nawasara-ui::badge>
                    </td>
                    <td class="px-6 py-4">
                        <div class="text-sm font-medium text-neutral-800 dark:text-neutral-100 truncate max-w-[280px]">
                            {{ $finding->displayName() }}
                        </div>
                        <div class="text-xs text-neutral-400 dark:text-neutral-500 truncate max-w-[280px]">
                            <span class="font-medium text-neutral-500 dark:text-neutral-400">{{ $finding->isHttpSource() ? 'HTTP' : 'SQL' }}</span>
                            ·
                            @if ($finding->isHttpSource() && $finding->scan_path && $finding->scan_path !== '/')
                                {{ $finding->db_name }}{{ $finding->scan_path }}
                            @elseif ($finding->site_url)
                                {{ $finding->site_url }}
                            @else
                                {{ $finding->db_name }}
                            @endif
                        </div>
                    </td>
                    <td class="px-6 py-4 text-sm text-neutral-600 dark:text-neutral-300 whitespace-nowrap">
                        {{ $finding->threatLabel() }}
                    </td>
                    <td class="px-6 py-4 text-sm font-semibold text-neutral-700 dark:text-neutral-200">
                        {{ $finding->score }}
                    </td>
                    <td class="px-6 py-4">
                        <x-nawasara-ui::badge :color="$finding->statusColor()">{{ $finding->statusLabel() }}</x-nawasara-ui::badge>
                    </td>
                    <td class="px-6 py-4 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                        {{ $finding->last_detected_at?->diffForHumans() ?? '-' }}
                    </td>
                    <td class="px-6 py-4 text-right">
                        <x-nawasara-ui::dropdown-menu-action :id="$finding->id" :items="$items" />
                    </td>
                </tr>
            @empty
                <tr>
                    <td colspan="7" class="px-6 py-6">
                        @if ($this->isDefaultView)
                            <x-nawasara-ui::empty-state inline variant="celebrate" icon="lucide-shield-check"
                                title="Tidak ada temuan yang perlu ditangani"
                                description="Semua temuan dalam rentang waktu ini sudah selesai atau ditandai false positive." />
                        @else
                            <x-nawasara-ui::empty-state inline icon="lucide-search-x"
                                title="Tidak ada yang cocok"
                                description="Ubah kata kunci atau saringannya. Saringan Status bawaan hanya menampilkan Terbuka dan Diakui." />
                        @endif
                    </td>
                </tr>
            @endforelse
        </x-slot:table>
    </x-nawasara-ui::table>

    <div class="mt-4">
        {{ $this->rows->links() }}
    </div>
</div>
