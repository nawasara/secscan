<?php

namespace Nawasara\Secscan\Services;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Lightweight HTTP fetcher for the F2 HTTP probe scanner.
 *
 * Responsibilities:
 * - Per-host rate limiting (configurable delay between requests)
 * - Per-host daily quota (avoid hammering OPD sites)
 * - Per-host backoff on repeated failure / Cloudflare challenge detection
 * - Cache-busting query param so CF doesn't serve cached pre-injection pages
 * - Normalise body to UTF-8 plain text for detector consumption
 */
class SiteHttpFetcher
{
    // User-Agent strings used in probing.
    public const UA_GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
    public const UA_BROWSER   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36';

    private int $timeoutSeconds;
    private int $delayMs;
    private int $dailyQuota;
    private int $backoffAfterFailures;
    private int $backoffMinutes;
    private int $maxBodyBytes;

    public function __construct()
    {
        $this->timeoutSeconds      = (int) config('nawasara-secscan.http_probe.timeout_seconds', 15);
        $this->delayMs             = (int) config('nawasara-secscan.http_probe.delay_ms_per_host', 2000);
        $this->dailyQuota          = (int) config('nawasara-secscan.http_probe.daily_quota_per_host', 200);
        $this->backoffAfterFailures = (int) config('nawasara-secscan.http_probe.backoff_after_failures', 3);
        $this->backoffMinutes      = (int) config('nawasara-secscan.http_probe.backoff_minutes', 30);
        $this->maxBodyBytes        = (int) config('nawasara-secscan.http_probe.max_body_kb', 2048) * 1024;
    }

    /**
     * Fetch a URL and return a structured result, or null on hard failure.
     *
     * @param  string  $hostname  e.g. "diskominfo.ponorogo.go.id"
     * @param  string  $path      e.g. "/" or "/wp-login.php"
     * @param  string  $ua        UA_GOOGLEBOT | UA_BROWSER
     * @param  bool    $cacheBust Append ?_nws_t= to bypass CF edge cache
     */
    public function fetch(
        string $hostname,
        string $path = '/',
        string $ua = self::UA_GOOGLEBOT,
        bool $cacheBust = true,
    ): ?array {
        // 1. Backoff check — host had too many failures recently
        if ($this->inCooldown($hostname)) {
            Log::debug('[secscan-http] host in cooldown, skip', ['host' => $hostname]);
            return null;
        }

        // 2. Daily quota check
        $quotaKey = "secscan:quota:{$hostname}:" . now()->format('Y-m-d');
        if (Cache::get($quotaKey, 0) >= $this->dailyQuota) {
            Log::debug('[secscan-http] daily quota exceeded', ['host' => $hostname]);
            return null;
        }

        // 3. Per-host rate limit — honour delay between requests
        $this->throttle($hostname);

        // 4. Build URL
        $url = 'https://' . ltrim($hostname, '/') . '/' . ltrim($path, '/');
        if ($cacheBust) {
            $url .= (str_contains($url, '?') ? '&' : '?') . '_nws_t=' . (int) (microtime(true) * 1000);
        }

        // 5. Execute request
        try {
            $response = Http::withHeaders([
                'User-Agent' => $ua,
                'Accept'     => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language' => 'id-ID,id;q=0.9,en;q=0.8',
            ])
                ->timeout($this->timeoutSeconds)
                ->withoutRedirecting()   // we track redirects manually below
                ->get($url);

            Cache::increment($quotaKey, 1, now()->endOfDay());

            $statusCode  = $response->status();
            $body        = $response->body();
            $headers     = $response->headers();
            $isChallenge = $this->isCloudflareChallenge($statusCode, $body, $headers);

            // Follow up to 3 redirects manually so we can detect chain hijacks
            $redirectChain = [];
            $finalUrl      = $url;
            $hops          = 0;
            $current       = $response;

            while (in_array($current->status(), [301, 302, 303, 307, 308], true) && $hops < 3) {
                $location = $current->header('Location');
                if (! $location) break;
                $redirectChain[] = ['from' => $finalUrl, 'to' => $location, 'status' => $current->status()];
                $finalUrl = $location;
                $hops++;

                try {
                    $current = Http::withHeaders(['User-Agent' => $ua])
                        ->timeout($this->timeoutSeconds)
                        ->withoutRedirecting()
                        ->get($finalUrl);
                } catch (\Throwable) {
                    break;
                }
            }

            // Use final response body if we followed redirects
            if ($hops > 0) {
                $body       = $current->body();
                $statusCode = $current->status();
                $headers    = $current->headers();
            }

            // Truncate oversized bodies
            if (strlen($body) > $this->maxBodyBytes) {
                $body = substr($body, 0, $this->maxBodyBytes);
            }

            if ($isChallenge) {
                $this->recordFailure($hostname);
            } else {
                $this->clearFailures($hostname);
            }

            return [
                'url'            => $url,
                'final_url'      => $finalUrl,
                'status_code'    => $statusCode,
                'is_challenge'   => $isChallenge,
                'redirect_chain' => $redirectChain,
                'body'           => $body,
                'body_length'    => strlen($body),
                'content_type'   => $response->header('Content-Type') ?? '',
                'cf_cache'       => $response->header('CF-Cache-Status') ?? null,
                'error'          => null,
            ];
        } catch (ConnectionException $e) {
            $this->recordFailure($hostname);
            Log::debug('[secscan-http] connection error', ['host' => $hostname, 'error' => $e->getMessage()]);
            return ['url' => $url, 'error' => $e->getMessage(), 'status_code' => 0];
        } catch (\Throwable $e) {
            $this->recordFailure($hostname);
            Log::debug('[secscan-http] fetch error', ['host' => $hostname, 'error' => $e->getMessage()]);
            return ['url' => $url, 'error' => $e->getMessage(), 'status_code' => 0];
        }
    }

    /**
     * Fetch the same path with both Googlebot and browser UA to detect cloaking.
     * Returns ['bot' => result, 'browser' => result, 'cloaking_detected' => bool].
     */
    public function fetchBoth(string $hostname, string $path = '/'): array
    {
        $bot     = $this->fetch($hostname, $path, self::UA_GOOGLEBOT);
        $browser = $this->fetch($hostname, $path, self::UA_BROWSER, false);

        $cloaking = false;
        if ($bot && $browser && ! $bot['error'] && ! $browser['error']) {
            $botLen     = $bot['body_length'] ?? 0;
            $browserLen = $browser['body_length'] ?? 0;
            // Size difference > 20% of the larger body is a strong cloaking signal
            $sizeDiff = abs($botLen - $browserLen);
            $larger   = max($botLen, $browserLen);
            if ($larger > 0 && ($sizeDiff / $larger) > 0.20) {
                $cloaking = true;
            }
        }

        return ['bot' => $bot, 'browser' => $browser, 'cloaking_detected' => $cloaking];
    }

    // -------------------------------------------------------------------------
    // Rate limiting & backoff helpers
    // -------------------------------------------------------------------------

    private function throttle(string $hostname): void
    {
        $lockKey = "secscan:lock:{$hostname}";
        $waited  = 0;
        while (Cache::has($lockKey) && $waited < 10) {
            usleep(200_000); // 200ms polling
            $waited++;
        }
        // Set lock for delay duration
        Cache::put($lockKey, true, (int) ceil($this->delayMs / 1000) + 1);
    }

    private function inCooldown(string $hostname): bool
    {
        return Cache::has("secscan:cooldown:{$hostname}");
    }

    private function recordFailure(string $hostname): void
    {
        $key   = "secscan:fail:{$hostname}";
        $count = Cache::increment($key);
        Cache::put($key, $count, now()->addHour());

        if ($count >= $this->backoffAfterFailures) {
            Cache::put("secscan:cooldown:{$hostname}", true, now()->addMinutes($this->backoffMinutes));
            Log::warning('[secscan-http] host entered cooldown', ['host' => $hostname, 'failures' => $count]);
        }
    }

    private function clearFailures(string $hostname): void
    {
        Cache::forget("secscan:fail:{$hostname}");
    }

    private function isCloudflareChallenge(int $status, string $body, array $headers): bool
    {
        if (isset($headers['cf-mitigated'])) {
            return true;
        }
        if ($status === 403 && str_contains($body, 'cdn-cgi/challenge-platform')) {
            return true;
        }
        if ($status === 429) {
            return true;
        }
        return false;
    }

    /**
     * Strip scripts/styles and collapse whitespace for cleaner detector input.
     */
    public function normalizeBody(string $html): string
    {
        // Remove script and style blocks entirely
        $clean = preg_replace('#<(script|style)[^>]*>.*?</\1>#is', ' ', $html) ?? $html;
        // Strip remaining tags
        $clean = strip_tags($clean);
        // Collapse whitespace
        $clean = preg_replace('/\s+/', ' ', $clean) ?? $clean;
        return mb_convert_encoding(trim($clean), 'UTF-8', 'auto');
    }
}
