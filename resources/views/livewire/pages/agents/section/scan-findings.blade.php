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

    {{-- Filters --}}
    <div class="flex items-center gap-2 mb-3">
        <x-nawasara-ui::filter-panel
            :state="['filterStatus' => $filterStatus, 'filterSeverity' => $filterSeverity, 'filterCategory' => $filterCategory]"
            :dimensions="['filterStatus' => 'Status', 'filterSeverity' => 'Severity', 'filterCategory' => 'Kategori']">
            <x-nawasara-ui::filter-group
                label="Status"
                model="filterStatus"
                :items="['open' => 'Open', 'acknowledged' => 'Acknowledged', 'resolved' => 'Resolved', 'false_positive' => 'False Positive']" />
            <x-nawasara-ui::filter-group
                label="Severity"
                model="filterSeverity"
                :items="['critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium']" />
            <x-nawasara-ui::filter-group
                label="Kategori"
                model="filterCategory"
                :items="['webshell' => 'Webshell', 'backdoor' => 'Backdoor', 'exploit' => 'Exploit Artifact', 'integrity' => 'File Integrity']" />
        </x-nawasara-ui::filter-panel>
    </div>

    <div data-filter-chips class="mb-3"></div>

    @if ($findings->isEmpty())
        <x-nawasara-ui::empty-state inline variant="celebrate"
            icon="lucide-shield-check"
            title="Tidak ada scan finding"
            description="{{ $filterStatus === 'open' ? 'Tidak ada file berbahaya terdeteksi.' : 'Tidak ada finding dengan filter ini.' }}" />
    @else
        <x-nawasara-ui::table
            :headers="['Severity', 'Kategori', 'Signature', 'Path', 'Status', 'Terdeteksi', '']"
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
                            <div class="text-xs text-neutral-500 dark:text-neutral-400 font-mono">{{ $finding->signature_id }}</div>
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
                        <td class="px-4 py-3">
                            <div class="flex items-center gap-1">
                                @if ($finding->isOpen())
                                    <x-nawasara-ui::icon-button
                                        icon="lucide-check"
                                        tooltip="Acknowledge"
                                        placement="left"
                                        wire:click="openTriage({{ $finding->id }}, 'acknowledge')" />
                                    <x-nawasara-ui::icon-button
                                        icon="lucide-shield-off"
                                        tooltip="False Positive"
                                        placement="left"
                                        wire:click="openTriage({{ $finding->id }}, 'false_positive')" />
                                @endif
                                @if (in_array($finding->status, ['open', 'acknowledged']))
                                    <x-nawasara-ui::icon-button
                                        icon="lucide-check-check"
                                        tooltip="Mark Resolved"
                                        placement="left"
                                        wire:click="openTriage({{ $finding->id }}, 'resolve')" />
                                @endif
                            </div>
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
