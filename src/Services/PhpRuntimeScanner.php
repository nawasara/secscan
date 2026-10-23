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
 * Token API WHM di Vault tidak berhak membaca versi PHP (diuji: "Permission
 * denied" untuk php_get_vhost_versions), jadi dibaca lewat SSH root dengan
 * kunci dari Vault (SshConnection). Instance tanpa kunci SSH dilewati dan
 * disebut di hasilnya, bukan dianggap kosong.
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

        $seen = [];
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

                if ($found !== null) {
                    PhpRuntime::record(PhpRuntime::SOURCE_EXTERNAL, $host, null, $found, $this->levels);
                    $seen[] = $host;
                }
            }
        }

        // Situs yang tidak lagi terlihat ber-PHP (dipindah, dimatikan, atau
        // berhenti memamerkan dirinya) dibuang hanya bila pemindaian ini
        // benar-benar berjalan; DNS kosong tidak boleh mengosongkan daftar.
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
        if (! OutboundUrlGuard::check($next)['ok']) {
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

        foreach (app(\Nawasara\Whm\Services\WhmClient::class)->instances() as $instance) {
            $ssh = app(\Nawasara\Whm\Services\SshConnection::class)->forInstance($instance)->withTimeout(60);

            if (! $ssh->isConfigured()) {
                $result[$instance] = ['error' => 'kunci SSH belum diisi di Vault'];

                continue;
            }

            try {
                $rows = self::parseWhm($ssh->exec(self::WHM_SCRIPT));
            } catch (\Throwable $e) {
                Log::warning('secscan.php_monitor.whm_failed', ['instance' => $instance, 'error' => $e->getMessage()]);
                $result[$instance] = ['error' => mb_substr($e->getMessage(), 0, 160)];

                continue;
            }

            if ($rows === []) {
                $result[$instance] = ['error' => 'whmapi1 tidak mengembalikan vhost'];

                continue;
            }

            foreach ($rows as $row) {
                PhpRuntime::record(PhpRuntime::SOURCE_WHM, $row['vhost'], $instance, [
                    'handler' => $row['handler'],
                    'php_version' => $row['php_version'],
                    'detected_via' => 'whmapi1',
                ], $this->levels);
            }

            PhpRuntime::where('source', PhpRuntime::SOURCE_WHM)
                ->where('origin', $instance)
                ->whereNotIn('target', array_column($rows, 'vhost'))
                ->delete();

            $result[$instance] = ['vhosts' => count($rows)];
        }

        return $result;
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
