<?php

namespace Nawasara\Secscan\Support;

/**
 * Decides whether an IP must never be auto-blocked. Checked FIRST in the
 * Decision Engine (fail-safe): if anything here matches, the IP is spared.
 *
 * Four layers:
 *   1. Cloudflare edge ranges — blocking these would blackhole CF → every site
 *      down. Safety net even though mod_remoteip now gives us real client IPs.
 *   2. Operator-supplied CIDRs — office/OPD public IPs, internal servers,
 *      monitoring (config `autoblock.whitelist_cidrs`).
 *   3. Known search-engine crawler ranges (Googlebot/Bingbot) — so SEO isn't
 *      harmed by a mis-block.
 *   4. Loopback / private / reserved — never meaningful to block at the edge.
 */
class IpWhitelist
{
    /** Cloudflare published IPv4 ranges (api.cloudflare.com/client/v4/ips). */
    private const CLOUDFLARE_V4 = [
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    ];

    /** Coarse but safe crawler ranges (Googlebot / Bingbot / common). */
    private const SEARCH_BOTS = [
        '66.249.64.0/19',   // Googlebot
        '64.233.160.0/19',  // Google
        '216.239.32.0/19',  // Google
        '157.55.39.0/24',   // Bingbot
        '207.46.13.0/24',   // Bingbot
        '40.77.167.0/24',   // Bingbot
    ];

    /** Loopback / private / link-local / reserved — never edge-blockable. */
    private const RESERVED = [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
        '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8',
    ];

    /**
     * @return array{whitelisted:bool, reason:?string}
     */
    public static function check(string $ip): array
    {
        $ip = trim($ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            // Malformed / empty → treat as whitelisted (never block garbage).
            return ['whitelisted' => true, 'reason' => 'invalid_ip'];
        }

        // IPv6 handled conservatively: only match the CF v6 prefixes we know;
        // anything else IPv6 is spared for now (blocks target IPv4 attackers).
        if (str_contains($ip, ':')) {
            return ['whitelisted' => true, 'reason' => 'ipv6_unsupported'];
        }

        if (self::inAny($ip, self::RESERVED)) {
            return ['whitelisted' => true, 'reason' => 'reserved'];
        }

        if (config('nawasara-secscan.autoblock.whitelist_cloudflare', true)
            && self::inAny($ip, self::CLOUDFLARE_V4)) {
            return ['whitelisted' => true, 'reason' => 'cloudflare'];
        }

        if (config('nawasara-secscan.autoblock.whitelist_search_bots', true)
            && self::inAny($ip, self::SEARCH_BOTS)) {
            return ['whitelisted' => true, 'reason' => 'search_bot'];
        }

        $custom = (array) config('nawasara-secscan.autoblock.whitelist_cidrs', []);
        if (self::inAny($ip, $custom)) {
            return ['whitelisted' => true, 'reason' => 'custom'];
        }

        return ['whitelisted' => false, 'reason' => null];
    }

    public static function isWhitelisted(string $ip): bool
    {
        return self::check($ip)['whitelisted'];
    }

    /** @param array<int,string> $cidrs */
    private static function inAny(string $ip, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            $cidr = trim($cidr);
            if ($cidr !== '' && self::inCidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    /** IPv4 CIDR membership test via bitmask. */
    private static function inCidr(string $ip, string $cidr): bool
    {
        if (! str_contains($cidr, '/')) {
            return $ip === $cidr;
        }
        [$subnet, $bits] = explode('/', $cidr, 2);
        $bits = (int) $bits;

        $ipLong     = ip2long($ip);
        $subnetLong = ip2long($subnet);
        if ($ipLong === false || $subnetLong === false || $bits < 0 || $bits > 32) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }
        $mask = -1 << (32 - $bits);

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
