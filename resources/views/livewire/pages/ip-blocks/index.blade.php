<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')], ['label' => 'IP Blocks']]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="IP Blocks"
            description="Auto-block Decision Engine — IP penyerang yang di-block di Cloudflare edge."
            :count="$stats['active'] . ' aktif'">
            <x-nawasara-ui::export-button permission="secscan.export" tooltip="Ekspor daftar block" />
        </x-nawasara-ui::page-header>

        {{-- Dry-run banner: makes it obvious blocks aren't enforced yet --}}
        @if (config('nawasara-secscan.autoblock.dry_run', true) && config('nawasara-secscan.autoblock.enabled', false))
            <div class="mb-4 flex items-center gap-2 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-800 dark:border-amber-700/50 dark:bg-amber-900/20 dark:text-amber-300">
                <x-lucide-flask-conical class="size-4 shrink-0" />
                <span><strong>Mode dry-run aktif.</strong> Decision Engine mencatat keputusan block tapi <strong>belum benar-benar mem-block di Cloudflare</strong>. Amati daftar ini, lalu matikan <code>SECSCAN_AUTOBLOCK_DRYRUN</code> untuk mengaktifkan block asli.</span>
            </div>
        @elseif (! config('nawasara-secscan.autoblock.enabled', false))
            <div class="mb-4 flex items-center gap-2 rounded-lg border border-neutral-300 bg-neutral-50 px-4 py-3 text-sm text-neutral-600 dark:border-neutral-700 dark:bg-neutral-800/40 dark:text-neutral-400">
                <x-lucide-power-off class="size-4 shrink-0" />
                <span>Auto-block <strong>nonaktif</strong> (<code>SECSCAN_AUTOBLOCK_ENABLED=false</code>). Decision Engine tidak berjalan.</span>
            </div>
        @endif

        {{-- Stats --}}
        <div class="grid grid-cols-2 md:grid-cols-3 gap-3 mb-6">
            <x-nawasara-ui::stat-card compact icon="lucide-shield-ban" label="Block Aktif" :value="$stats['active']" color="danger" />
            <x-nawasara-ui::stat-card compact icon="lucide-flask-conical" label="Dry-run (belum enforced)" :value="$stats['dry_run']" color="warning" />
            <x-nawasara-ui::stat-card compact icon="lucide-shield-check" label="Sudah Di-unblock" :value="$stats['removed']" color="neutral" />
        </div>

        {{-- Toolbar --}}
        <div class="flex flex-wrap items-center gap-2 mb-4">
            <x-nawasara-ui::filter-panel label="Filter"
                :state="['filterStatus' => $filterStatus]"
                :dimensions="['filterStatus' => 'Status']">
                <x-nawasara-ui::filter-group label="Status" model="filterStatus"
                    :items="['active' => 'Aktif', 'removed' => 'Di-unblock']" icon="lucide-shield" />
            </x-nawasara-ui::filter-panel>
            <x-nawasara-ui::search-input model="search" placeholder="Cari IP…" />
        </div>

        <x-nawasara-ui::page.card>
            @if ($blocks->isEmpty())
                <x-nawasara-ui::empty-state icon="lucide-shield-check" variant="celebrate"
                    title="Belum ada IP di-block"
                    description="Decision Engine akan mencatat IP penyerang di sini saat ambang terpenuhi." />
            @else
                <x-nawasara-ui::table stickyLast
                    :headers="['IP', 'Alasan', 'Mode', 'Sumber', 'Insiden', 'Di-block', 'Status', '']">
                    <x-slot:table>
                        @foreach ($blocks as $b)
                            <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                                <td class="px-4 py-3 font-mono text-sm text-neutral-800 dark:text-neutral-100">{{ $b->ip }}</td>
                                <td class="px-4 py-3 text-sm text-neutral-700 dark:text-neutral-200">{{ ucwords(str_replace('_', ' ', $b->reason)) }}</td>
                                <td class="px-4 py-3">
                                    @if ($b->dry_run)
                                        <x-nawasara-ui::badge color="warning">dry-run</x-nawasara-ui::badge>
                                    @else
                                        <x-nawasara-ui::badge color="danger">enforced</x-nawasara-ui::badge>
                                    @endif
                                </td>
                                <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400">
                                    {{ $b->blocked_by ? 'Manual' : 'Otomatis' }}
                                </td>
                                <td class="px-4 py-3 text-sm">
                                    @if ($b->incident_id)
                                        <a href="{{ route('nawasara-secscan.incidents') }}" wire:navigate
                                           class="text-emerald-600 dark:text-emerald-400 hover:underline">#{{ $b->incident_id }}</a>
                                    @else
                                        <span class="text-neutral-400">—</span>
                                    @endif
                                </td>
                                <td class="px-4 py-3 text-sm text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                    <span title="{{ $b->blocked_at?->format('d M Y H:i:s') }}">{{ $b->blocked_at?->diffForHumans() }}</span>
                                </td>
                                <td class="px-4 py-3">
                                    @if ($b->isActive())
                                        <x-nawasara-ui::badge color="danger">Aktif</x-nawasara-ui::badge>
                                    @else
                                        <x-nawasara-ui::badge color="neutral">Di-unblock</x-nawasara-ui::badge>
                                    @endif
                                </td>
                                <td class="px-4 py-3 text-right">
                                    @if ($b->isActive())
                                        <x-nawasara-ui::button color="neutral" size="sm"
                                            wire:click="unblock({{ $b->id }})"
                                            wire:confirm="Buka blokir IP {{ $b->ip }}? Ini mengembalikan akses IP tersebut.">
                                            Unblock
                                        </x-nawasara-ui::button>
                                    @endif
                                </td>
                            </tr>
                        @endforeach
                    </x-slot:table>
                </x-nawasara-ui::table>
                <div class="mt-4">{{ $blocks->links() }}</div>
            @endif
        </x-nawasara-ui::page.card>
    </x-nawasara-ui::page.container>
</div>
