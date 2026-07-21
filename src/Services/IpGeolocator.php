<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Resolve an attacker IP to a human-readable origin (country, city, network).
 *
 * Analysts ask "where is this from?" before anything else — an IP that belongs
 * to a hosting provider abroad reads very differently from one inside the
 * office range, and that judgement changes what they do next.
 *
 * Lookups go to a free public API, so this is deliberately defensive:
 *
 *   - Results are cached for a month. Geolocation of a given IP effectively
 *     never changes, and the page is opened repeatedly for the same IP.
 *   - Failures cache a null result for a short time, so an outage or a rate
 *     limit doesn't make every page load pay the timeout again.
 *   - Private/reserved ranges never leave the building — they're answered
 *     locally, both to save a pointless round-trip and to avoid telling a
 *     third party about internal addressing.
 *   - Anything unexpected returns null rather than throwing. Origin is
 *     context, never a reason for the timeline to fail to render.
 */
class IpGeolocator
{
    /**
     * @return array{country:?string, country_code:?string, city:?string, org:?string, is_private:bool}|null
     */
    public function locate(string $ip): ?array
    {
        $ip = trim($ip);

        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        if ($this->isPrivate($ip)) {
            return [
                'country' => 'Jaringan lokal',
                'country_code' => null,
                'city' => null,
                'org' => 'Private / reserved range',
                'is_private' => true,
            ];
        }

        $ttl = (int) config('nawasara-secscan.geolocation.cache_days', 30);

        return Cache::remember(
            'secscan:geoip:'.$ip,
            now()->addDays(max(1, $ttl)),
            fn () => $this->fetch($ip)
        );
    }

    /**
     * Best-effort one-line summary for display, e.g.
     * "Cheyenne, Amerika Serikat — Microsoft Corporation".
     */
    public function describe(string $ip): ?string
    {
        $geo = $this->locate($ip);

        if ($geo === null) {
            return null;
        }

        $place = array_filter([$geo['city'], $geo['country']]);
        $line = implode(', ', $place);

        if (! empty($geo['org'])) {
            $line = $line === '' ? $geo['org'] : $line.' — '.$geo['org'];
        }

        return $line === '' ? null : $line;
    }

    protected function fetch(string $ip): ?array
    {
        if (! config('nawasara-secscan.geolocation.enabled', true)) {
            return null;
        }

        $endpoint = (string) config('nawasara-secscan.geolocation.endpoint', 'https://ipinfo.io');
        $timeout = (int) config('nawasara-secscan.geolocation.timeout', 5);
        $token = (string) config('nawasara-secscan.geolocation.token', '');

        try {
            $request = Http::timeout(max(1, $timeout))->acceptJson();

            if ($token !== '') {
                $request = $request->withToken($token);
            }

            $response = $request->get(rtrim($endpoint, '/').'/'.$ip.'/json');

            if (! $response->successful()) {
                Log::info('[secscan] geoip lookup failed', [
                    'ip' => $ip,
                    'status' => $response->status(),
                ]);

                // Cache the miss briefly so a rate limit doesn't cost a timeout
                // on every subsequent page view.
                Cache::put('secscan:geoip:'.$ip, null, now()->addMinutes(15));

                return null;
            }

            $data = $response->json();

            if (! is_array($data) || isset($data['bogon'])) {
                return null;
            }

            return [
                'country' => $this->countryName($data['country'] ?? null),
                'country_code' => $data['country'] ?? null,
                'city' => $data['city'] ?? null,
                'org' => $data['org'] ?? null,
                'is_private' => false,
            ];
        } catch (\Throwable $e) {
            Log::info('[secscan] geoip lookup error: '.$e->getMessage(), ['ip' => $ip]);

            Cache::put('secscan:geoip:'.$ip, null, now()->addMinutes(15));

            return null;
        }
    }

    protected function isPrivate(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * Indonesian names for the countries that actually show up in our logs;
     * anything else falls back to the raw ISO code, which is still readable.
     */
    protected function countryName(?string $code): ?string
    {
        if ($code === null || $code === '') {
            return null;
        }

        $names = [
            'ID' => 'Indonesia',
            'US' => 'Amerika Serikat',
            'CN' => 'Tiongkok',
            'RU' => 'Rusia',
            'SG' => 'Singapura',
            'NL' => 'Belanda',
            'DE' => 'Jerman',
            'FR' => 'Prancis',
            'GB' => 'Inggris',
            'IN' => 'India',
            'VN' => 'Vietnam',
            'BR' => 'Brasil',
            'JP' => 'Jepang',
            'KR' => 'Korea Selatan',
            'HK' => 'Hong Kong',
            'TW' => 'Taiwan',
            'MY' => 'Malaysia',
            'TH' => 'Thailand',
            'UA' => 'Ukraina',
            'CA' => 'Kanada',
            'AU' => 'Australia',
            'SE' => 'Swedia',
            'PL' => 'Polandia',
            'TR' => 'Turki',
            'IR' => 'Iran',
        ];

        return $names[strtoupper($code)] ?? strtoupper($code);
    }
}
