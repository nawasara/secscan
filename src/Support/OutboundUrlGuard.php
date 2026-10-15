<?php

namespace Nawasara\Secscan\Support;

/**
 * Penjaga permintaan HTTP keluar dari pemindai (SiteHttpFetcher).
 *
 * Audit keamanan 15 Oktober 2026, temuan R10: pemindai mengikuti redirect
 * tanpa memeriksa tujuannya. Situs OPD yang disusupi cukup menjawab
 * `Location: http://169.254.169.254/` atau `http://10.1.1.23:3306/` dan
 * server Nawasara akan menghubungi jaringan dalam atas nama penyerang (SSRF).
 *
 * Aturannya diperiksa di SETIAP lompatan, bukan hanya di URL awal:
 *  - skema hanya http/https;
 *  - nama host di-resolve, dan SEMUA alamatnya harus publik. Satu saja yang
 *    privat/khusus sudah cukup untuk menolak, karena curl bebas memilih yang
 *    mana yang dipakai.
 *
 * Alamat yang lolos dikembalikan supaya pemanggil dapat "menyematkannya" ke
 * curl (CURLOPT_RESOLVE). Tanpa itu, DNS dapat menjawab alamat publik saat
 * diperiksa lalu alamat dalam saat curl me-resolve ulang (DNS rebinding).
 */
class OutboundUrlGuard
{
    /**
     * Rentang yang tidak tercakup FILTER_FLAG_NO_PRIV_RANGE / NO_RES_RANGE di
     * semua versi PHP, jadi dicek eksplisit. Daftar ini sengaja berlebih:
     * menolak satu alamat aneh jauh lebih murah daripada satu SSRF.
     */
    private const BLOCKED_CIDRS = [
        '0.0.0.0/8',
        '10.0.0.0/8',
        '100.64.0.0/10',   // CGNAT
        '127.0.0.0/8',
        '169.254.0.0/16',  // link-local, termasuk metadata cloud 169.254.169.254
        '172.16.0.0/12',
        '192.0.0.0/24',
        '192.168.0.0/16',
        '198.18.0.0/15',
        '224.0.0.0/4',     // multicast
        '240.0.0.0/4',
        '::/128',
        '::1/128',
        '::ffff:0:0/96',   // IPv4-mapped: ::ffff:127.0.0.1 tidak boleh lolos
        '64:ff9b::/96',
        'fc00::/7',        // unique local
        'fe80::/10',       // link-local
        'ff00::/8',        // multicast
    ];

    /**
     * True bila alamat IP aman dihubungi dari server (publik, bukan khusus).
     */
    public static function isPublicIp(string $ip): bool
    {
        $ip = trim($ip, " \t\n\r\0\x0B[]");

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        foreach (self::BLOCKED_CIDRS as $cidr) {
            if (self::inCidr($ip, $cidr)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Periksa satu URL. Mengembalikan ['ok' => true, 'host', 'port', 'ip']
     * atau ['ok' => false, 'reason'].
     *
     * @param  (callable(string): list<string>)|null  $resolver  untuk tes; bawaan memakai DNS sistem
     * @return array{ok: bool, reason?: string, host?: string, port?: int, ip?: string}
     */
    public static function check(string $url, ?callable $resolver = null): array
    {
        $parts = parse_url($url);
        if ($parts === false || empty($parts['scheme']) || empty($parts['host'])) {
            return ['ok' => false, 'reason' => 'url_invalid'];
        }

        $scheme = strtolower($parts['scheme']);
        if (! in_array($scheme, ['http', 'https'], true)) {
            return ['ok' => false, 'reason' => 'scheme_not_allowed'];
        }

        // Kredensial di URL (user:pass@host) tidak pernah dipakai situs OPD
        // yang sah, dan sering dipakai untuk mengelabui pemeriksa host.
        if (isset($parts['user']) || isset($parts['pass'])) {
            return ['ok' => false, 'reason' => 'userinfo_not_allowed'];
        }

        $host = strtolower(trim($parts['host'], '[]'));
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));

        $ips = filter_var($host, FILTER_VALIDATE_IP) !== false
            ? [$host]
            : ($resolver ? $resolver($host) : self::resolve($host));

        if ($ips === []) {
            return ['ok' => false, 'reason' => 'dns_unresolved'];
        }

        foreach ($ips as $ip) {
            if (! self::isPublicIp($ip)) {
                return ['ok' => false, 'reason' => 'non_public_ip:'.$ip];
            }
        }

        return ['ok' => true, 'host' => $host, 'port' => $port, 'ip' => $ips[0]];
    }

    /**
     * Ubah nilai header Location (bisa relatif) menjadi URL absolut terhadap
     * URL yang sedang diminta.
     */
    public static function absolutize(string $location, string $base): string
    {
        $location = trim($location);
        if (preg_match('#^[a-z][a-z0-9+.-]*:#i', $location)) {
            return $location; // sudah absolut (termasuk javascript:, ditolak check())
        }

        $b = parse_url($base) ?: [];
        $scheme = $b['scheme'] ?? 'https';
        $authority = ($b['host'] ?? '').(isset($b['port']) ? ':'.$b['port'] : '');

        if (str_starts_with($location, '//')) {
            return $scheme.':'.$location;
        }

        if (str_starts_with($location, '/')) {
            return $scheme.'://'.$authority.$location;
        }

        $dir = isset($b['path']) ? preg_replace('#/[^/]*$#', '/', $b['path']) : '/';

        return $scheme.'://'.$authority.($dir ?: '/').$location;
    }

    /** @return list<string> */
    private static function resolve(string $host): array
    {
        $ips = [];

        $records = @dns_get_record($host, DNS_A | DNS_AAAA) ?: [];
        foreach ($records as $r) {
            if (! empty($r['ip'])) {
                $ips[] = $r['ip'];
            }
            if (! empty($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }

        if ($ips === []) {
            $v4 = @gethostbynamel($host) ?: [];
            $ips = array_values($v4);
        }

        return array_values(array_unique($ips));
    }

    private static function inCidr(string $ip, string $cidr): bool
    {
        [$subnet, $bits] = explode('/', $cidr, 2);
        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $bits = (int) $bits;
        $bytes = intdiv($bits, 8);
        $rem = $bits % 8;

        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }

        if ($rem === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $rem)) & 0xFF;

        return (ord($ipBin[$bytes]) & $mask) === (ord($subnetBin[$bytes]) & $mask);
    }
}
