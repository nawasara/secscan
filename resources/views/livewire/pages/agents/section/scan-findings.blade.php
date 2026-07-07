<div>
    {{-- Stats bar --}}
    <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
        <x-nawasara-ui::stat-card compact
            icon="lucide-scan-search"
            label="Total Findings"
            :value="$stats['total']"
            color="neutral" />
        <x-nawasara-ui::stat-card compact
            icon="lucide-triangle-alert"
            label="Open"
            :value="$stats['open']"
            color="warning" />
        <x-nawasara-ui::stat-card compact
            icon="lucide-octagon-alert"
            label="Critical Open"
            :value="$stats['critical']"
            color="danger" />
        <x-nawasara-ui::stat-card compact
            icon="lucide-bug"
            label="Webshells"
            :value="$stats['webshells']"
            color="danger" />
    </div>

    {{-- Filters: filter-panel + time-window --}}
    <div class="flex flex-wrap items-center gap-2 mb-3">
        <x-nawasara-ui::filter-panel
            label="Filter"
            :state="['filterStatus' => $filterStatus, 'filterSeverity' => $filterSeverity, 'filterCategory' => $filterCategory]"
            :dimensions="['filterStatus' => 'Status', 'filterSeverity' => 'Severity', 'filterCategory' => 'Kategori']">
            <x-nawasara-ui::filter-group
                label="Status"
                model="filterStatus"
                :items="['open' => 'Open', 'acknowledged' => 'Acknowledged', 'resolved' => 'Resolved', 'false_positive' => 'False Positive']"
                icon="lucide-list-checks" />
            <x-nawasara-ui::filter-group
                label="Severity"
                model="filterSeverity"
                :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium']"
                icon="lucide-octagon-alert" />
            <x-nawasara-ui::filter-group
                label="Kategori"
                model="filterCategory"
                :items="['webshell' => 'Webshell', 'backdoor' => 'Backdoor', 'exploit' => 'Exploit Artifact', 'integrity' => 'File Integrity']"
                icon="lucide-bug" />
        </x-nawasara-ui::filter-panel>

        <x-nawasara-ui::time-window
            :window="$window" :from="$from" :to="$to"
            :presets="['today' => 'Hari ini', '7d' => '7 hari', '30d' => '30 hari', 'all' => 'Semua']" />
    </div>

    <div wire:ignore data-filter-chips class="mb-3"></div>

    @if ($findings->isEmpty())
        <x-nawasara-ui::empty-state inline variant="celebrate"
            icon="lucide-shield-check"
            title="Tidak ada scan finding"
            description="{{ $filterStatus === 'open' ? 'Tidak ada file berbahaya terdeteksi.' : 'Tidak ada finding dengan filter ini.' }}" />
    @else
        <x-nawasara-ui::table
            :headers="['Severity', 'Kategori', 'Signature', 'Path', 'Status', 'Terdeteksi', 'Terakhir', '']"
            :stickyLast="true">
            <x-slot:table>
                @foreach ($findings as $finding)
                    <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                        <td class="px-4 py-3 whitespace-nowrap">
                            <x-nawasara-ui::badge :color="$finding->severityColor()">
                                {{ ucfirst($finding->severity) }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-3 whitespace-nowrap">
                            <x-nawasara-ui::badge color="neutral">
                                {{ $finding->categoryLabel() }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-3">
                            <div class="text-sm font-medium text-neutral-800 dark:text-neutral-100">{{ $finding->sig_name }}</div>
                            <div class="flex items-center gap-1.5 mt-0.5">
                                <span class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">{{ $finding->signature_id }}</span>
                                @if ($finding->mitre_technique)
                                    <a href="{{ $finding->mitreUrl() }}" target="_blank" rel="noopener"
                                       title="MITRE ATT&CK: {{ $finding->mitreName() }}"
                                       class="inline-flex items-center rounded px-1.5 py-0.5 text-xs font-mono font-medium bg-sky-50 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300 hover:bg-sky-100 dark:hover:bg-sky-900/50">
                                        {{ $finding->mitre_technique }}
                                    </a>
                                @endif
                            </div>
                        </td>
                        <td class="px-4 py-3 max-w-xs">
                            <div class="font-mono text-xs text-neutral-700 dark:text-neutral-200 break-all leading-relaxed" title="{{ $finding->path }}">
                                {{ $finding->path }}
                            </div>
                            @if ($finding->matched_line)
                                <div class="mt-1 text-xs text-neutral-500 dark:text-neutral-400 truncate font-mono" title="{{ $finding->matched_line }}">
                                    {{ Str::limit($finding->matched_line, 60) }}
                                </div>
                            @endif
                        </td>
                        <td class="px-4 py-3 whitespace-nowrap">
                            <x-nawasara-ui::badge :color="$finding->statusColor()">
                                {{ ucfirst(str_replace('_', ' ', $finding->status)) }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            <span title="{{ $finding->detected_at?->format('d M Y H:i:s') }}">
                                {{ $finding->detected_at?->diffForHumans() }}
                            </span>
                        </td>
                        <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            <span title="{{ ($finding->last_seen_at ?? $finding->detected_at)?->format('d M Y H:i:s') }}">
                                {{ ($finding->last_seen_at ?? $finding->detected_at)?->diffForHumans() }}
                            </span>
                        </td>
                        <td class="px-4 py-3 text-right">
                            @php
                                $triageItems = [];
                                if ($finding->isOpen()) {
                                    $triageItems[] = ['type' => 'click', 'label' => 'Acknowledge', 'wire:click' => "openTriage({$finding->id}, 'acknowledge')", 'modal' => 'scan-triage-'.$agentDbId, 'icon' => 'lucide-check'];
                                    $triageItems[] = ['type' => 'click', 'label' => 'False Positive', 'wire:click' => "openTriage({$finding->id}, 'false_positive')", 'modal' => 'scan-triage-'.$agentDbId, 'icon' => 'lucide-shield-off'];
                                }
                                if (in_array($finding->status, ['open', 'acknowledged'])) {
                                    $triageItems[] = ['type' => 'click', 'label' => 'Mark Resolved', 'wire:click' => "openTriage({$finding->id}, 'resolve')", 'modal' => 'scan-triage-'.$agentDbId, 'icon' => 'lucide-check-check'];
                                }
                            @endphp
                            @if (! empty($triageItems))
                                <x-nawasara-ui::dropdown-menu-action :id="$finding->id" :items="$triageItems" />
                            @else
                                <span class="text-neutral-400 dark:text-neutral-600 text-sm">—</span>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </x-slot:table>
        </x-nawasara-ui::table>

        <div class="mt-4">
            {{ $findings->links() }}
        </div>
    @endif

    {{-- Triage modal --}}
    <x-nawasara-ui::modal :id="'scan-triage-' . $agentDbId" title="Triage Finding">
        @if ($triageId)
            <div class="space-y-4">
                <p class="text-sm text-neutral-600 dark:text-neutral-300">
                    @if ($triageAction === 'acknowledge')
                        Tandai finding ini sebagai <strong>Acknowledged</strong> (sedang diselidiki).
                    @elseif ($triageAction === 'resolve')
                        Tandai finding ini sebagai <strong>Resolved</strong> (sudah ditangani/file dihapus).
                    @elseif ($triageAction === 'false_positive')
                        Tandai finding ini sebagai <strong>False Positive</strong> (bukan ancaman nyata).
                    @endif
                </p>

                <div>
                    <x-nawasara-ui::form.textarea
                        label="Catatan (opsional)"
                        wire:model="triageNote"
                        :rows="3"
                        placeholder="Tuliskan keterangan atau langkah penanganan..." />
                </div>
            </div>

            <x-slot:footer>
                <x-nawasara-ui::button
                    color="neutral"
                    x-on:click="$dispatch('close-modal', 'scan-triage-{{ $agentDbId }}')">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button
                    :color="$triageAction === 'false_positive' ? 'warning' : ($triageAction === 'resolve' ? 'success' : 'primary')"
                    wire:click="confirmTriage">
                    @if ($triageAction === 'acknowledge') Acknowledge
                    @elseif ($triageAction === 'resolve') Resolve
                    @else False Positive
                    @endif
                </x-nawasara-ui::button>
            </x-slot:footer>
        @endif
    </x-nawasara-ui::modal>
</div>
