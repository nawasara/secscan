<div>
    <x-slot name="breadcrumb">
        <livewire:nawasara-ui.shared-components.breadcrumb
            :items="[
                ['label' => 'Security Scan', 'url' => route('nawasara-secscan.dashboard')],
                ['label' => 'Notifikasi'],
            ]" />
    </x-slot>

    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Notifikasi Keamanan"
            description="Atur siapa yang menerima laporan harian dan peringatan insiden.">
            <x-nawasara-ui::button color="neutral" variant="outline" wire:click="sendTest"
                wire:loading.attr="disabled">
                <x-lucide-send class="size-4" />
                Kirim Uji
            </x-nawasara-ui::button>
        </x-nawasara-ui::page-header>

        <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">

            {{-- Laporan harian --}}
            <x-nawasara-ui::page.card>
                <div class="flex items-start gap-3 mb-5">
                    <div class="size-9 rounded-lg grid place-items-center bg-emerald-50 text-emerald-600 dark:bg-emerald-900/30 dark:text-emerald-400 shrink-0">
                        <x-lucide-mail class="size-5" />
                    </div>
                    <div>
                        <h3 class="font-semibold text-neutral-800 dark:text-neutral-100">Laporan Harian</h3>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">
                            Rekap 24 jam: jumlah insiden, jenis serangan, IP penyerang teratas,
                            situs yang diserang, dan IP yang di-block.
                        </p>
                    </div>
                </div>

                <div class="space-y-4">
                    <div>
                        <x-nawasara-ui::form.label value="Email Penerima" />
                        <x-nawasara-ui::form.textarea wire:model="digestRecipients" :rows="3"
                            placeholder="csirt@ponorogo.go.id, kominfo@ponorogo.go.id" />
                        <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                            Pisahkan dengan koma atau baris baru. Kosongkan untuk memakai
                            penerima peringatan <em>critical</em>.
                        </p>
                        @error('digestRecipients')
                            <span class="mt-1 block text-xs text-red-600 dark:text-red-400">{{ $message }}</span>
                        @enderror
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <x-nawasara-ui::form.label value="Jam Kirim" />
                            <x-nawasara-ui::form.input type="time" wire:model="digestAt" />
                            @error('digestAt')
                                <span class="mt-1 block text-xs text-red-600 dark:text-red-400">{{ $message }}</span>
                            @enderror
                        </div>
                        <div class="flex flex-col justify-end gap-2 pb-1">
                            <x-nawasara-ui::form.checkbox wire:model="digestEnabled" label="Aktifkan laporan harian" />
                            <x-nawasara-ui::form.checkbox wire:model="digestSendWhenEmpty" label="Kirim walau tidak ada insiden" />
                        </div>
                    </div>
                </div>
            </x-nawasara-ui::page.card>

            {{-- Peringatan real-time --}}
            <x-nawasara-ui::page.card>
                <div class="flex items-start gap-3 mb-5">
                    <div class="size-9 rounded-lg grid place-items-center bg-rose-50 text-rose-600 dark:bg-rose-900/30 dark:text-rose-400 shrink-0">
                        <x-lucide-bell-ring class="size-5" />
                    </div>
                    <div>
                        <h3 class="font-semibold text-neutral-800 dark:text-neutral-100">Peringatan Insiden</h3>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">
                            Dikirim seketika saat insiden terdeteksi. Email di sini
                            <strong>ditambahkan</strong> ke penerima berdasarkan peran.
                        </p>
                    </div>
                </div>

                <div class="space-y-4">
                    <div>
                        <x-nawasara-ui::form.label value="Email Tambahan" />
                        <x-nawasara-ui::form.textarea wire:model="alertRecipients" :rows="3"
                            placeholder="kadis@ponorogo.go.id" />
                        <p class="mt-1 text-xs text-neutral-500 dark:text-neutral-400">
                            Untuk mailbox bersama atau pihak tanpa akun Nawasara.
                        </p>
                        @error('alertRecipients')
                            <span class="mt-1 block text-xs text-red-600 dark:text-red-400">{{ $message }}</span>
                        @enderror
                    </div>

                    <div class="rounded-lg border border-neutral-200 dark:border-neutral-700 p-3 text-sm">
                        <p class="font-medium text-neutral-700 dark:text-neutral-200 mb-1">Penerima berdasarkan peran</p>
                        <p class="text-xs text-neutral-500 dark:text-neutral-400">
                            <strong>Critical</strong> → peran <code>developer</code> + <code>sysadmin</code><br>
                            <strong>Warning / Info</strong> → peran <code>sysadmin</code>
                        </p>
                    </div>
                </div>
            </x-nawasara-ui::page.card>
        </div>

        <div class="mt-4 flex justify-end">
            <x-nawasara-ui::button color="success" wire:click="save" wire:loading.attr="disabled">
                <x-lucide-save class="size-4" />
                Simpan Pengaturan
            </x-nawasara-ui::button>
        </div>
    </x-nawasara-ui::page.container>
</div>
