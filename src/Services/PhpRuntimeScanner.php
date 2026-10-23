<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Http\Client\Pool;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Nawasara\Secscan\Models\PhpRuntime;
use Nawasara\Secscan\Support\OutboundUrlGuard;
use Nawasara\Secscan\Support\PhpPatchLevels;

/**
 * Mengumpulkan versi PHP dari luar (hostname DNS Cloudflare) dan dari dalam
 * server WHM. Laporan agen masuk lewat AgentController::heartbeat.
 *
 * ## Dari luar: apa yang terlihat dan tidak
 *
 * Header `X-Powered-By: PHP/x.y.z` memberi versi lengkap. Tanpa itu, PHP
 * masih dikenali dari cookie sesinya (PHPSESSID, *_session Laravel,
 * ci_session) atau tautan `wp-json` WordPress, tetapi versinya tidak:
 * barisnya berstatus "tersembunyi", dan versi sebenarnya hanya bisa dibaca
 * dari dalam (WHM atau agen). Situs yang masih memamerkan versinya ditandai
 * tersendiri, karena header itu menghemat pekerjaan penyerang memilih
 * sasaran.
 *
 * Survei manual 23 Oktober 2026 hanya membuka halaman depan tanpa mengikuti
 * redirect dan menemukan 12 dari 274 hostname. Di sini satu redirect diikuti,
 * karena banyak aplikasi langsung mengalihkan ke /login.
 *
 * ## Dari dalam WHM
 *
 * Lewat API WHM memakai token root yang sudah ada di Vault, dengan syarat
 * tokennya ber-ACL "all" (WHM → Manage API Tokens). Token dengan ACL
 * terbatas dijawab "Permission denied"; untuk server seperti itu SSH root
 * dengan kunci dari Vault (SshConnection) dipakai sebagai cadangan. Server
 * yang keduanya gagal dicatat di log beserta alasannya, bukan dianggap
 * kosong.
 */
class PhpRuntimeScanner
{
    /** Vhost bawaan cPanel yang bukan situs siapa pun. */
    protected const WHM_NOISE = '/(\.cpx\.local|\.cpanel\.site)$/i';

    public function __construct(protected PhpPatchLevels $levels) {}

    // ------------------------------------------------------------------
    // Dari luar
    // ------------------------------------------------------------------

    /** @return array{scanned:int, php:int, skipped:int} */
    public function scanExternal(): array
    {
        $hosts = $this->externalHosts();
        $timeout = (int) config('nawasara-secscan.php_monitor.timeout_seconds', 8);
        $concurrency = max(1, (int) config('nawasara-secscan.php_monitor.concurrency', 20));

        $allowed = [];
        $skipped = 0;
        foreach ($hosts as $host) {
            // Rekaman DNS bisa menunjuk alamat dalam; pemindai tidak boleh
            // menjadi jalan masuk ke jaringan internal.
            if (OutboundUrlGuard::check('https://'.$host.'/')['ok']) {
                $allowed[] = $host;
            } else {
                $skipped++;
            }
        }

        $inside = $this->insideTargets();
        $seen = [];
        $notPhp = [];
        foreach (array_chunk($allowed, $concurrency) as $chunk) {
            $responses = Http::pool(fn (Pool $pool) => array_map(
                fn ($h) => $pool->as($h)->timeout($timeout)->withoutRedirecting()
                    ->withOptions(['verify' => false])
                    ->withUserAgent('Nawasara-Secscan/php-monitor')
                    ->get('https://'.$h.'/'),
                $chunk
            ));

            foreach ($responses as $host => $response) {
                if (! $response instanceof Response) {
                    continue;
                }

                $found = self::fingerprint($response->headers());

                if ($found === null && $response->redirect()) {
                    $found = $this->followOnce($response, 'https://'.$host.'/', $timeout);
                }

                if ($found !== null && isset($inside[$host])) {
                    // Sudah terbaca dari dalam (WHM atau agen), lengkap dengan
                    // versinya: baris dari luar hanya menggandakannya.
                    $seen[] = $host;
                } elseif ($found !== null) {
                    PhpRuntime::record(PhpRuntime::SOURCE_EXTERNAL, $host, null, $found, $this->levels);
                    $seen[] = $host;
                } else {
                    $notPhp[] = $host;
                }
            }
        }

        // Menjawab tetapi tidak ber-PHP: buang sekarang juga (situs pindah
        // teknologi, atau baris lama hasil salah deteksi).
        if ($notPhp !== []) {
            PhpRuntime::where('source', PhpRuntime::SOURCE_EXTERNAL)->whereIn('target', $notPhp)->delete();
        }

        // Tidak menjawab: diberi 3 hari, karena situs yang sedang mati
        // sebentar bukan berarti PHP-nya sudah hilang. DNS kosong tidak boleh
        // mengosongkan daftar, jadi hanya bila pemindaian benar-benar berjalan.
        if ($allowed !== []) {
            PhpRuntime::where('source', PhpRuntime::SOURCE_EXTERNAL)
                ->whereNotIn('target', $seen ?: ['-'])
                ->where('last_seen_at', '<', now()->subDays(3))
                ->delete();
        }

        return ['scanned' => count($allowed), 'php' => count($seen), 'skipped' => $skipped];
    }

    protected function followOnce(Response $response, string $base, int $timeout): ?array
    {
        $location = $response->header('Location');
        if ($location === '') {
            return null;
        }

        $next = OutboundUrlGuard::absolutize($location, $base);
        if (! self::sameSite($base, $next) || ! OutboundUrlGuard::check($next)['ok']) {
            return null;
        }

        try {
            $second = Http::timeout($timeout)->withoutRedirecting()
                ->withOptions(['verify' => false])
                ->withUserAgent('Nawasara-Secscan/php-monitor')
                ->get($next);
        } catch (\Throwable) {
            return null;
        }

        // Cookie sesi sering dipasang di jawaban redirect pertama, versinya di
        // halaman tujuan: gabungkan keduanya.
        return self::fingerprint(array_merge_recursive($response->headers(), $second->headers()));
    }

    /**
     * Redirect hanya diikuti di dalam host yang sama (termasuk www).
     *
     * ⚠️ Pemindaian pertama di prod (23 Oktober 2026) mengikuti redirect ke
     * mana saja: kisara.ponorogo.go.id mengalihkan ke ponorogo.go.id, dan
     * PHP milik situs tujuan tercatat atas nama kisara (yang Keycloak, Java).
     */
    public static function sameSite(string $from, string $to): bool
    {
        $a = strtolower((string) parse_url($from, PHP_URL_HOST));
        $b = strtolower((string) parse_url($to, PHP_URL_HOST));

        return $a !== '' && preg_replace('/^www\./', '', $a) === preg_replace('/^www\./', '', $b);
    }

    /** @return array<string, int> sasaran yang sudah terbaca dari dalam, sebagai kunci */
    protected function insideTargets(): array
    {
        return PhpRuntime::whereIn('source', [PhpRuntime::SOURCE_WHM, PhpRuntime::SOURCE_AGENT])
            ->distinct()->pluck('target')->flip()->all();
    }

    /**
     * Buang baris "dari luar" untuk situs yang sudah terbaca dari dalam.
     *
     * Pindaian luar berjalan lebih dulu, jadi situs yang baru pertama kali
     * terbaca dari WHM masih punya baris luar dari putaran yang sama. Tanpa
     * ini setiap situs WHM tampil dua kali, sekali sebagai "tersembunyi"
     * (dilaporkan 23 Oktober 2026: puskesmassooko dan sooko).
     *
     * ⚠️ Daftarnya diambil dulu baru dihapus: MySQL menolak DELETE yang
     * subquery-nya membaca tabel yang sama (galat 1093).
     */
    public function dropExternalDuplicates(): int
    {
        $deleted = 0;
        foreach (array_chunk(array_keys($this->insideTargets()), 500) as $chunk) {
            $deleted += PhpRuntime::where('source', PhpRuntime::SOURCE_EXTERNAL)->whereIn('target', $chunk)->delete();
        }

        return $deleted;
    }

    /** @return list<string> */
    protected function externalHosts(): array
    {
        if (! Schema::hasTable('nawasara_cloudflare_dns_records')) {
            return [];
        }

        return DB::table('nawasara_cloudflare_dns_records')
            ->whereIn('type', ['A', 'AAAA', 'CNAME'])
            ->where('name', 'not like', '*%')
            ->distinct()
            ->orderBy('name')
            ->pluck('name')
            ->map(fn ($n) => strtolower(rtrim((string) $n, '.')))
            ->unique()
            ->values()
            ->all();
    }

    /**
     * Kenali PHP dari header jawaban HTTP.
     *
     * @param  array<string, string|list<string>>  $headers
     * @return array{php_version:?string, detected_via:string, exposes_version:bool}|null
     */
    public static function fingerprint(array $headers): ?array
    {
        $get = function (string $name) use ($headers): array {
            foreach ($headers as $key => $value) {
                if (strcasecmp($key, $name) === 0) {
                    return array_map('strval', (array) $value);
                }
            }

            return [];
        };

        foreach ($get('X-Powered-By') as $value) {
            if (preg_match('/PHP\/(\d+\.\d+(?:\.\d+)?)/i', $value, $m)) {
                return ['php_version' => $m[1], 'detected_via' => 'x-powered-by', 'exposes_version' => true];
            }
        }

        foreach ($get('Set-Cookie') as $cookie) {
            $name = strtolower(trim(explode('=', $cookie, 2)[0]));
            // Cookie Cloudflare (CF_Session milik Cloudflare Access, __cf_bm)
            // dipasang di depan situs apa pun dan cocok dengan pola
            // *_session; tanpa pengecualian ini aplikasi Node dan Go di
            // belakang Access ikut tercatat sebagai PHP.
            if (str_starts_with($name, 'cf_') || str_starts_with($name, '__cf')) {
                continue;
            }
            if ($name === 'phpsessid' || $name === 'ci_session' || str_ends_with($name, '_session') || $name === 'xsrf-token') {
                return ['php_version' => null, 'detected_via' => 'cookie', 'exposes_version' => false];
            }
        }

        foreach ($get('Link') as $link) {
            if (str_contains($link, 'wp-json')) {
                return ['php_version' => null, 'detected_via' => 'wordpress', 'exposes_version' => false];
            }
        }

        foreach ($get('X-Powered-By') as $value) {
            if (stripos($value, 'php') !== false) {
                return ['php_version' => null, 'detected_via' => 'x-powered-by', 'exposes_version' => false];
            }
        }

        return null;
    }

    // ------------------------------------------------------------------
    // Dari dalam WHM
    // ------------------------------------------------------------------

    /**
     * Versi lengkap tiap ea-php, lalu handler tiap vhost. Dua perintah
     * terpisah dipisah penanda, supaya cukup satu sambungan SSH.
     */
    public const WHM_SCRIPT = <<<'SH'
for d in /opt/cpanel/ea-php*/root/usr/bin/php; do [ -x "$d" ] && echo "VER $(echo $d | grep -o 'ea-php[0-9]*') $($d -r 'echo PHP_VERSION;' 2>/dev/null)"; done
echo '---VHOSTS---'
whmapi1 --output=json php_get_vhost_versions 2>/dev/null
SH;

    /** @return array<string, array{vhosts:int}|array{error:string}> */
    public function scanWhm(): array
    {
        $result = [];

        if (! class_exists(\Nawasara\Whm\Services\WhmClient::class)) {
            return $result;
        }

        $whm = app(\Nawasara\Whm\Services\WhmClient::class);

        foreach ($whm->instances() as $instance) {
            // API dulu: cukup token root ber-ACL "all" yang sudah ada di Vault.
            // SSH hanya cadangan untuk server yang tokennya dibatasi.
            [$rows, $via, $error] = $this->whmRowsViaApi($whm->forInstance($instance));

            if ($rows === null) {
                $ssh = app(\Nawasara\Whm\Services\SshConnection::class)->forInstance($instance)->withTimeout(60);

                if ($ssh->isConfigured()) {
                    try {
                        $rows = self::parseWhm($ssh->exec(self::WHM_SCRIPT));
                        $via = 'ssh';
                    } catch (\Throwable $e) {
                        $error .= '; SSH: '.mb_substr($e->getMessage(), 0, 120);
                    }
                }
            }

            if ($rows === null || $rows === []) {
                Log::warning('secscan.php_monitor.whm_failed', ['instance' => $instance, 'error' => $error]);
                $result[$instance] = ['error' => $error ?: 'tidak ada vhost'];

                continue;
            }

            foreach ($rows as $row) {
                PhpRuntime::record(PhpRuntime::SOURCE_WHM, $row['vhost'], $instance, [
                    'handler' => $row['handler'],
                    'php_version' => $row['php_version'],
                    'detected_via' => $via,
                ], $this->levels);
            }

            PhpRuntime::where('source', PhpRuntime::SOURCE_WHM)
                ->where('origin', $instance)
                ->whereNotIn('target', array_column($rows, 'vhost'))
                ->delete();

            $result[$instance] = ['vhosts' => count($rows), 'via' => $via];
        }

        $this->dropExternalDuplicates();

        return $result;
    }

    /**
     * Handler tiap vhost (php_get_vhost_versions) lalu versi lengkap tiap
     * ea-php dari paket CLI-nya (package_manager_get_package_info).
     *
     * ⚠️ php_get_installed_versions hanya memberi nama handler ("ea-php82"),
     * padahal yang menentukan rentan atau tidak adalah nomor patch-nya
     * (8.2.30 vs 8.2.35). Versi paket ea-phpNN-php-cli sama dengan versi PHP
     * yang dijalankan handler itu ("8.2.35-1+1.1.cpanel").
     *
     * Keduanya butuh token ber-ACL "all"; token dengan ACL terbatas dijawab
     * "Permission denied" dengan HTTP 200, bukan galat HTTP.
     *
     * @return array{0: ?list<array{vhost:string, handler:string, php_version:?string}>, 1: string, 2: string}
     */
    protected function whmRowsViaApi($client): array
    {
        if (! $client->isConfigured()) {
            return [null, 'api', 'token WHM belum diisi di Vault'];
        }

        // ⚠️ Batas 60 detik bawaan klien WHM terlalu pendek di sini: di Alpine
        // (100 vhost) panggilan ini dua kali habis waktu tanpa satu byte pun
        // pada 23 Oktober 2026, padahal 20 menit sebelumnya lancar. Dinaikkan
        // hanya selama pemindaian ini; fitur WHM lain tetap 60 detik.
        $previous = config('nawasara-whm.timeout');
        config(['nawasara-whm.timeout' => 180]);

        try {
            try {
                $vhosts = $client->rawJsonApi('php_get_vhost_versions');
            } catch (\Throwable $e) {
                return [null, 'api', 'API: '.mb_substr($e->getMessage(), 0, 120)];
            }
            if ((int) ($vhosts['metadata']['result'] ?? 0) !== 1) {
                return [null, 'api', 'API: '.mb_substr((string) ($vhosts['metadata']['reason'] ?? 'gagal'), 0, 120)];
            }

            $handlers = array_values(array_unique(array_filter(array_map(
                fn ($v) => (string) ($v['version'] ?? ''),
                (array) ($vhosts['data']['versions'] ?? [])
            ), fn ($h) => preg_match('/^ea-php\d+$/', $h))));

            $params = [];
            foreach ($handlers as $i => $handler) {
                $params['package-'.($i + 1)] = $handler.'-php-cli';
            }

            // Info paket gagal bukan alasan membuang daftar vhost: pakai versi
            // terakhir yang diketahui untuk handler yang sama. Versi ea-php
            // hanya berubah saat server diperbarui.
            try {
                $packages = $params === [] ? [] : $client->rawJsonApi('package_manager_get_package_info', $params);
            } catch (\Throwable $e) {
                Log::warning('secscan.php_monitor.whm_package_info_failed', [
                    'instance' => $client->instance(), 'error' => mb_substr($e->getMessage(), 0, 160),
                ]);
                $packages = [];
            }
        } finally {
            config(['nawasara-whm.timeout' => $previous]);
        }

        $known = PhpRuntime::where('source', PhpRuntime::SOURCE_WHM)
            ->where('origin', (string) $client->instance())
            ->whereNotNull('php_version')
            ->pluck('php_version', 'handler')
            ->all();

        return [self::parseWhmApi($vhosts, $packages, $known), 'whm-api', ''];
    }

    /**
     * @return list<array{vhost:string, handler:string, php_version:?string}>
     */
    public static function parseWhmApi(array $vhosts, array $packages, array $fallback = []): array
    {
        $versions = $fallback;
        foreach ((array) ($packages['data']['packages'] ?? []) as $pkg) {
            $name = (string) ($pkg['package'] ?? '');
            $installed = (string) ($pkg['version_installed'] ?? '');
            if (preg_match('/^(ea-php\d+)-php-cli$/', $name, $m) && preg_match('/^\d+\.\d+\.\d+/', $installed, $v)) {
                $versions[$m[1]] = $v[0];
            }
        }

        $rows = [];
        foreach ((array) ($vhosts['data']['versions'] ?? []) as $vhost) {
            $name = strtolower((string) ($vhost['vhost'] ?? ''));
            $handler = (string) ($vhost['version'] ?? '');
            if ($name === '' || preg_match(self::WHM_NOISE, $name)) {
                continue;
            }
            $rows[] = ['vhost' => $name, 'handler' => $handler, 'php_version' => $versions[$handler] ?? null];
        }

        return $rows;
    }

    /** @return list<array{vhost:string, handler:string, php_version:?string}> */
    public static function parseWhm(string $output): array
    {
        [$versionsPart, $jsonPart] = array_pad(explode('---VHOSTS---', $output, 2), 2, '');

        $versions = [];
        foreach (preg_split('/\R/', $versionsPart) as $line) {
            if (preg_match('/^VER (ea-php\d+) (\d+\.\d+\.\d+)/', trim($line), $m)) {
                $versions[$m[1]] = $m[2];
            }
        }

        $data = json_decode(trim($jsonPart), true);
        $rows = [];
        foreach ((array) ($data['data']['versions'] ?? []) as $vhost) {
            $name = strtolower((string) ($vhost['vhost'] ?? ''));
            $handler = (string) ($vhost['version'] ?? '');
            if ($name === '' || preg_match(self::WHM_NOISE, $name)) {
                continue;
            }
            $rows[] = ['vhost' => $name, 'handler' => $handler, 'php_version' => $versions[$handler] ?? null];
        }

        return $rows;
    }

    // ------------------------------------------------------------------
    // Laporan agen
    // ------------------------------------------------------------------

    /**
     * Simpan runtime yang dilaporkan satu agen, dan buang yang tidak lagi
     * dilaporkannya (container dihapus, ea-php dicopot).
     *
     * @param  list<array{target:string, handler?:?string, version?:?string}>  $runtimes
     */
    public function recordAgent(string $agentName, array $runtimes): void
    {
        $targets = [];
        foreach ($runtimes as $rt) {
            $target = trim((string) ($rt['target'] ?? ''));
            if ($target === '') {
                continue;
            }
            $targets[] = mb_substr(strtolower($target), 0, 191);
            PhpRuntime::record(PhpRuntime::SOURCE_AGENT, $target, $agentName, [
                'handler' => $rt['handler'] ?? null,
                'php_version' => $rt['version'] ?? null,
                'detected_via' => 'agent',
            ], $this->levels);
        }

        PhpRuntime::where('source', PhpRuntime::SOURCE_AGENT)
            ->where('origin', $agentName)
            ->whereNotIn('target', $targets ?: ['-'])
            ->delete();
    }
}
