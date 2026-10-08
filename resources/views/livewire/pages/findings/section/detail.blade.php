<div>
    @php
        $severityLabels = ['critical' => 'Kritis', 'warning' => 'Peringatan', 'info' => 'Info'];
        $statusLabels = \Nawasara\Secscan\Models\SecscanFinding::statusLabels();
    @endphp

    <x-nawasara-ui::modal id="secscan-finding-detail" title="Detail Temuan" maxWidth="2xl">
        @if ($this->detail)
            @php $d = $this->detail; @endphp
            <div class="space-y-4">
                <div class="flex items-center gap-2 flex-wrap">
                    <x-nawasara-ui::badge :color="$d->severityColor()">{{ $severityLabels[$d->severity] ?? ucfirst($d->severity) }}</x-nawasara-ui::badge>
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
                                -
                            @endif
                        </dd>
                    </div>
                    <div>
                        <dt class="text-xs text-neutral-500 dark:text-neutral-400">Jenis</dt>
                        <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->threatLabel() }}</dd>
                    </div>
                    <div>
                        <dt class="text-xs text-neutral-500 dark:text-neutral-400">Pertama terdeteksi</dt>
                        <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->first_detected_at?->translatedFormat('d M Y H:i') ?? '-' }}</dd>
                    </div>
                    <div>
                        <dt class="text-xs text-neutral-500 dark:text-neutral-400">Terakhir terdeteksi</dt>
                        <dd class="text-neutral-800 dark:text-neutral-100">{{ $d->last_detected_at?->diffForHumans() ?? '-' }}</dd>
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
                                    <span class="text-neutral-400 dark:text-neutral-500">(menampilkan {{ count($ev['samples']) }} contoh)</span>
                                @endif
                            </p>
                            <ul class="space-y-1.5">
                                @foreach ($ev['samples'] as $s)
                                    <li class="text-sm">
                                        <div class="text-neutral-800 dark:text-neutral-100 truncate">{{ $s['title'] ?? '-' }}</div>
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
                                    <span class="text-neutral-400 dark:text-neutral-500">{{ $h->created_at?->diffForHumans() }}</span>
                                    · {{ $h->status_from ? ($statusLabels[$h->status_from] ?? $h->status_from) : 'Baru' }}
                                    → <strong>{{ $statusLabels[$h->status_to] ?? $h->status_to }}</strong>
                                    · {{ $h->changed_by ? 'oleh petugas' : 'oleh pemindai' }}
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
                            <p class="text-xs text-neutral-500 dark:text-neutral-400">
                                Selesai: bila pemindai masih mendeteksinya, temuan terbuka lagi.
                                False positive: pemindai tidak akan membukanya lagi.
                            </p>
                        </div>
                    @endif
                @endcan
            </div>

            {{-- Tombol di footer berada di LUAR konten modal, jadi memakai wire:click, bukan form. --}}
            <x-slot:footer>
                @can('secscan.finding.triage')
                    @if ($d->isActive())
                        @if ($d->status === \Nawasara\Secscan\Models\SecscanFinding::STATUS_OPEN)
                            <x-nawasara-ui::button color="warning" variant="outline" wire:click="acknowledge">
                                Akui
                            </x-nawasara-ui::button>
                        @endif
                        <x-nawasara-ui::button color="neutral" variant="outline" wire:click="markFalsePositive">
                            False Positive
                        </x-nawasara-ui::button>
                        <x-nawasara-ui::button color="success" wire:click="resolve">
                            Tandai Selesai
                        </x-nawasara-ui::button>
                    @endif
                @endcan
            </x-slot:footer>
        @endif
    </x-nawasara-ui::modal>
</div>
