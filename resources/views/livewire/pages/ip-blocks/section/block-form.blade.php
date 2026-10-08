<div>
    <x-nawasara-ui::modal id="ip-block-form" title="Blokir IP">
        <div class="space-y-4">
            <div>
                <x-nawasara-ui::form.input type="text" label="Alamat IP" wire:model="ip" placeholder="mis. 203.0.113.7" />
                @error('ip') <p class="mt-1 text-xs text-red-600 dark:text-red-400">{{ $message }}</p> @enderror
            </div>
            <div>
                <x-nawasara-ui::form.input type="text" label="Alasan" wire:model="reason" placeholder="mis. Brute force panel admin" />
                @error('reason') <p class="mt-1 text-xs text-red-600 dark:text-red-400">{{ $message }}</p> @enderror
            </div>
            <p class="text-xs text-neutral-500 dark:text-neutral-400">
                Diblokir di Cloudflare untuk seluruh situs dan tidak kedaluwarsa. IP kantor, Cloudflare, dan mesin pencari ditolak.
            </p>
        </div>

        {{-- Footer berada di LUAR konten modal: wire:click, bukan submit form. --}}
        <x-slot:footer>
            <x-nawasara-ui::button color="neutral" variant="outline" x-on:click="$dispatch('close-modal', 'ip-block-form')">
                Batal
            </x-nawasara-ui::button>
            <x-nawasara-ui::button color="danger" wire:click="save">
                Blokir
            </x-nawasara-ui::button>
        </x-slot:footer>
    </x-nawasara-ui::modal>
</div>
