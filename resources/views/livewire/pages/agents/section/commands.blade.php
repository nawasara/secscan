<div>
    {{-- Header + Issue Command button --}}
    <div class="flex items-center justify-between mb-4">
        <div class="flex items-center gap-2">
            <p class="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">Perintah Eksekusi</p>
            @if ($this->pendingCount > 0)
                <x-nawasara-ui::badge color="warning">{{ $this->pendingCount }} menunggu</x-nawasara-ui::badge>
            @endif
        </div>
        <div class="flex items-center gap-2">
            <x-nawasara-ui::export-button
                permission="secscan.export"
                tooltip="Ekspor riwayat perintah" />
            <x-nawasara-ui::button
                color="primary"
                size="sm"
                icon="lucide-terminal"
                x-on:click="$dispatch('open-modal', { id: 'modal-issue-command', loading: false })"
                wire:click="$refresh">
                Kirim Perintah
            </x-nawasara-ui::button>
        </div>
    </div>

    {{-- Command history table --}}
    @if ($this->commands->isEmpty())
        <x-nawasara-ui::empty-state inline
            icon="lucide-terminal-square"
            title="Belum ada perintah"
            description="Kirim perintah eksekusi via tombol di atas. Semua perintah butuh approval sebelum dikirim ke agent." />
    @else
        <x-nawasara-ui::table
            :headers="['Aksi', 'Parameter', 'Status', 'Oleh', 'Waktu', '']"
            :stickyLast="true">
            <x-slot:table>
                @foreach ($this->commands as $cmd)
                    <tr class="hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                        <td class="px-4 py-3 text-sm font-medium text-neutral-800 dark:text-neutral-100">
                            {{ $cmd->actionLabel() }}
                        </td>
                        <td class="px-4 py-3 font-mono text-xs text-neutral-600 dark:text-neutral-300">
                            @if ($cmd->params)
                                @foreach ($cmd->params as $k => $v)
                                    <span class="text-neutral-500 dark:text-neutral-400">{{ $k }}=</span>{{ $v }}
                                @endforeach
                            @else
                                <span class="text-neutral-400 dark:text-neutral-500">—</span>
                            @endif
                        </td>
                        <td class="px-4 py-3">
                            <x-nawasara-ui::badge :color="$cmd->statusColor()">
                                {{ $cmd->statusLabel() }}
                            </x-nawasara-ui::badge>
                        </td>
                        <td class="px-4 py-3 text-xs text-neutral-500 dark:text-neutral-400">
                            @if ($cmd->approvedBy)
                                {{ $cmd->approvedBy->name }}
                            @elseif ($cmd->rejectedBy)
                                <span class="text-rose-600 dark:text-rose-400">{{ $cmd->rejectedBy->name }}</span>
                            @else
                                <span class="text-neutral-400 dark:text-neutral-500">—</span>
                            @endif
                        </td>
                        <td class="px-4 py-3 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                            @if ($cmd->exec_at)
                                <span title="{{ $cmd->exec_at->format('d M Y H:i:s') }}">{{ $cmd->exec_at->diffForHumans() }}</span>
                            @elseif ($cmd->approved_at)
                                <span title="{{ $cmd->approved_at->format('d M Y H:i:s') }}">{{ $cmd->approved_at->diffForHumans() }}</span>
                            @else
                                {{ $cmd->created_at->diffForHumans() }}
                            @endif
                        </td>
                        <td class="px-4 py-3">
                            @if ($cmd->isPending())
                                <div class="flex items-center gap-1.5 justify-end">
                                    <x-nawasara-ui::button
                                        color="success"
                                        size="xs"
                                        wire:click="approve({{ $cmd->id }})"
                                        wire:loading.attr="disabled">
                                        Setujui
                                    </x-nawasara-ui::button>
                                    <x-nawasara-ui::button
                                        color="danger"
                                        size="xs"
                                        wire:click="openReject({{ $cmd->id }})">
                                        Tolak
                                    </x-nawasara-ui::button>
                                </div>
                            @elseif ($cmd->status === 'completed' || $cmd->status === 'failed')
                                @if ($cmd->output || $cmd->error)
                                    <x-nawasara-ui::icon-button
                                        icon="lucide-terminal"
                                        tooltip="Lihat output"
                                        x-on:click="$dispatch('open-modal', { id: 'modal-cmd-output-{{ $cmd->id }}', loading: false })"
                                        placement="left" />
                                @endif
                            @endif
                        </td>
                    </tr>

                    {{-- Output modal per command (inline, lightweight) --}}
                    @if ($cmd->output || $cmd->error)
                        <x-nawasara-ui::modal id="modal-cmd-output-{{ $cmd->id }}" size="lg">
                            <x-slot:title>Output: {{ $cmd->actionLabel() }}</x-slot:title>
                            @if ($cmd->output)
                                <p class="text-xs font-semibold text-neutral-500 dark:text-neutral-400 mb-1">STDOUT</p>
                                <pre class="bg-neutral-900 text-emerald-400 text-xs p-3 rounded-lg overflow-auto max-h-64 whitespace-pre-wrap">{{ $cmd->output }}</pre>
                            @endif
                            @if ($cmd->error)
                                <p class="text-xs font-semibold text-rose-500 dark:text-rose-400 mt-3 mb-1">ERROR</p>
                                <pre class="bg-neutral-900 text-rose-400 text-xs p-3 rounded-lg overflow-auto max-h-32 whitespace-pre-wrap">{{ $cmd->error }}</pre>
                            @endif
                        </x-nawasara-ui::modal>
                    @endif
                @endforeach
            </x-slot:table>
        </x-nawasara-ui::table>
    @endif

    {{-- Issue command modal --}}
    <x-nawasara-ui::modal id="modal-issue-command" size="md">
        <x-slot:title>Kirim Perintah ke Agent</x-slot:title>

        <form wire:submit="issueCommand" class="space-y-4">
            <div>
                <x-nawasara-ui::form.select
                    label="Aksi"
                    wire:model.live="action"
                    placeholder="Pilih aksi..."
                    :options="[
                        'block_ip'               => 'Block IP',
                        'unblock_ip'             => 'Unblock IP',
                        'restart_nginx'          => 'Restart Nginx',
                        'reload_nginx'           => 'Reload Nginx',
                        'restart_apache'         => 'Restart Apache',
                        'reload_apache'          => 'Reload Apache',
                        'restart_php_fpm'        => 'Restart PHP-FPM',
                        'reload_php_fpm'         => 'Reload PHP-FPM',
                        'restart_mysql'          => 'Restart MySQL',
                        'artisan_queue_restart'  => 'Artisan queue:restart',
                        'artisan_optimize_clear' => 'Artisan optimize:clear',
                    ]" />
            </div>

            @if (in_array($action, ['block_ip', 'unblock_ip']))
                <div>
                    <x-nawasara-ui::form.input
                        label="IP Address"
                        wire:model="paramIp"
                        placeholder="1.2.3.4"
                        type="text" />
                </div>
            @endif

            @if (in_array($action, ['block_ip', 'restart_mysql', 'restart_php_fpm']))
                <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/50 p-3">
                    <p class="text-xs font-semibold text-amber-800 dark:text-amber-300">
                        Aksi ini bersifat destruktif dan membutuhkan konfirmasi sudo saat di-approve.
                    </p>
                </div>
            @endif

            <div class="rounded-lg bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-700/50 p-3">
                <p class="text-xs text-blue-700 dark:text-blue-300">
                    Perintah akan masuk ke antrean <strong>menunggu approval</strong> terlebih dahulu.
                    Admin lain perlu menyetujuinya sebelum dikirim ke agent.
                </p>
            </div>

            <div class="flex gap-2 justify-end pt-2">
                <x-nawasara-ui::button
                    color="neutral"
                    x-on:click="$dispatch('close-modal', 'modal-issue-command')">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button
                    type="submit"
                    color="primary"
                    wire:loading.attr="disabled">
                    Kirim ke Antrean
                </x-nawasara-ui::button>
            </div>
        </form>
    </x-nawasara-ui::modal>

    {{-- Reject reason modal --}}
    <x-nawasara-ui::modal id="modal-reject-command" size="sm">
        <x-slot:title>Tolak Perintah</x-slot:title>
        <form wire:submit="confirmReject" class="space-y-4">
            <div>
                <x-nawasara-ui::form.textarea
                    label="Alasan penolakan"
                    wire:model="rejectionReason"
                    :rows="3"
                    placeholder="Tuliskan alasan penolakan..." />
            </div>
            <div class="flex gap-2 justify-end">
                <x-nawasara-ui::button
                    color="neutral"
                    x-on:click="$dispatch('close-modal', 'modal-reject-command')">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button
                    type="submit"
                    color="danger"
                    wire:loading.attr="disabled">
                    Tolak Perintah
                </x-nawasara-ui::button>
            </div>
        </form>
    </x-nawasara-ui::modal>
</div>
