<div class="mb-6">
    {{-- Token pendaftaran agen (audit keamanan 15 Oktober 2026, T1).
         Installer agen wajib membawa token sekali pakai dari sini. --}}
    <x-nawasara-ui::page.card>
        <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-4">
            <div>
                <p class="text-sm font-semibold text-neutral-800 dark:text-neutral-100">Token Pendaftaran Agen</p>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Sekali pakai dan berbatas waktu. Agen yang mendaftar dengan token ini menunggu persetujuan
                    sebelum insidennya dapat memicu blokir IP.
                </p>
            </div>
            <x-nawasara-ui::button
                color="primary"
                size="sm"
                icon="lucide-key-round"
                x-on:click="$dispatch('open-modal', { id: 'agent-enrollment-form', loading: false })">
                Buat Token
            </x-nawasara-ui::button>
        </div>

        @if ($this->tokens->isEmpty())
            <x-nawasara-ui::empty-state inline icon="lucide-key-round"
                title="Belum ada token"
                description="Buat token sebelum memasang agen di server baru." />
        @else
            <x-nawasara-ui::table :headers="['Keterangan', 'Status', 'Dibuat', 'Berlaku sampai', 'Agen', '']" stickyLast>
                <x-slot:table>
                    @foreach ($this->tokens as $token)
                        <tr wire:key="enroll-{{ $token->id }}">
                            <td class="px-4 py-3 text-sm text-neutral-700 dark:text-neutral-200">
                                {{ $token->label ?? '-' }}
                            </td>
                            <td class="px-4 py-3">
                                <x-nawasara-ui::badge :color="$token->statusColor()">{{ $token->statusLabel() }}</x-nawasara-ui::badge>
                            </td>
                            <td class="px-4 py-3 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                {{ $token->created_at?->diffForHumans() }}
                                @if ($token->creator)
                                    <div>oleh {{ $token->creator->name }}</div>
                                @endif
                            </td>
                            <td class="px-4 py-3 text-xs text-neutral-500 dark:text-neutral-400 whitespace-nowrap">
                                {{ $token->expires_at?->format('d M Y H:i') }}
                            </td>
                            <td class="px-4 py-3 text-xs text-neutral-600 dark:text-neutral-300">
                                @if ($token->agent)
                                    {{ $token->agent->name }}
                                    @if ($token->used_from_ip)
                                        <div class="font-mono text-neutral-400 dark:text-neutral-500">{{ $token->used_from_ip }}</div>
                                    @endif
                                @else
                                    -
                                @endif
                            </td>
                            <td class="px-4 py-3 text-right">
                                @if ($token->statusLabel() === 'Aktif')
                                    <x-nawasara-ui::dropdown-menu-action :id="'enroll-'.$token->id" :items="[
                                        ['type' => 'click', 'label' => 'Cabut token', 'wire:click' => 'revokeToken('.$token->id.')',
                                         'icon' => 'lucide-ban', 'permission' => 'secscan.agent.enroll',
                                         'confirm' => 'Cabut token ini? Installer yang belum memakainya akan ditolak.'],
                                    ]" />
                                @endif
                            </td>
                        </tr>
                    @endforeach
                </x-slot:table>
            </x-nawasara-ui::table>
        @endif
    </x-nawasara-ui::page.card>

    <x-nawasara-ui::modal id="agent-enrollment-form" title="Buat Token Pendaftaran" maxWidth="md">
        <div class="space-y-4">
            <div>
                <x-nawasara-ui::form.input type="text" label="Keterangan" wire:model="label"
                    placeholder="mis. server web Dinkes" />
                @error('label') <p class="text-xs text-rose-600 dark:text-rose-400 mt-1">{{ $message }}</p> @enderror
            </div>
            <div>
                <x-nawasara-ui::form.select label="Masa Berlaku" wire:model="ttlHours"
                    :options="$this->ttlOptions()" :placeholder="null" />
                @error('ttlHours') <p class="text-xs text-rose-600 dark:text-rose-400 mt-1">{{ $message }}</p> @enderror
            </div>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Token hanya ditampilkan sekali setelah dibuat. Membuat token membutuhkan konfirmasi sudo.
            </p>
        </div>
        <x-slot:footer>
            <x-nawasara-ui::button color="neutral"
                x-on:click="$dispatch('close-modal', 'agent-enrollment-form')">Batal</x-nawasara-ui::button>
            <x-nawasara-ui::button color="primary" wire:click="issue" wire:loading.attr="disabled">
                Buat Token
            </x-nawasara-ui::button>
        </x-slot:footer>
    </x-nawasara-ui::modal>

    <x-nawasara-ui::modal id="agent-enrollment-result" title="Token Pendaftaran Dibuat" maxWidth="2xl">
        @if ($issuedToken)
            <div class="space-y-4">
                <div class="rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/50 p-3">
                    <p class="text-xs font-semibold text-amber-800 dark:text-amber-300">
                        Salin sekarang. Token ini tidak akan ditampilkan lagi.
                    </p>
                </div>
                <div>
                    <x-nawasara-ui::form.label value="Token" />
                    <pre class="mt-1 bg-neutral-100 dark:bg-neutral-900 text-neutral-800 dark:text-neutral-100 text-xs p-3 rounded-lg overflow-auto select-all">{{ $issuedToken }}</pre>
                </div>
                <div>
                    <x-nawasara-ui::form.label value="Perintah Pasang" />
                    <pre class="mt-1 bg-neutral-900 text-emerald-400 text-xs p-3 rounded-lg overflow-auto whitespace-pre-wrap break-all select-all">{{ $this->installCommand() }}</pre>
                </div>
                <p class="text-xs text-neutral-500 dark:text-neutral-400">
                    Setelah agen mendaftar, setujui agennya di tabel di bawah (menu titik tiga, Setujui agen).
                </p>
            </div>
        @endif
        <x-slot:footer>
            <x-nawasara-ui::button color="primary" wire:click="dismissToken">Sudah Saya Salin</x-nawasara-ui::button>
        </x-slot:footer>
    </x-nawasara-ui::modal>
</div>
