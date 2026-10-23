<?php

namespace Nawasara\Secscan\Tests;

use Nawasara\Secscan\Services\PhpRuntimeScanner;
use Nawasara\Secscan\Support\PhpPatchLevels;
use PHPUnit\Framework\TestCase;

/**
 * Pemantau versi PHP (PHP2Shell, CVE-2026-109618/109619). Versi di bawah ini
 * diambil dari survei 23 Oktober 2026.
 */
class PhpRuntimeMonitorTest extends TestCase
{
    private function levels(): PhpPatchLevels
    {
        return new PhpPatchLevels(['8.2.35', '8.3.36', '8.4.27', '8.5.12']);
    }

    public function test_golongan_versi_sesuai_survei(): void
    {
        $l = $this->levels();

        $this->assertSame('vulnerable', $l->classify('8.2.30'));   // penataanruang
        $this->assertSame('safe', $l->classify('8.2.35'));         // Ryder, Himalaya
        $this->assertSame('safe', $l->classify('8.4.27'));         // Nawasara
        $this->assertSame('vulnerable', $l->classify('8.4.26'));
        $this->assertSame('eol', $l->classify('8.1.34'));          // 6 situs Himalaya
        $this->assertSame('eol', $l->classify('7.4.33'));          // smep
        $this->assertSame('eol', $l->classify('5.6.31'));          // e-bmd
        $this->assertSame('safe', $l->classify('8.6.0'));          // cabang sesudah advisory
        $this->assertSame('hidden', $l->classify(null));
        $this->assertSame('hidden', $l->classify('8.2'));          // tanpa nomor patch
    }

    public function test_versi_tujuan_hanya_untuk_cabang_yang_ditambal(): void
    {
        $l = $this->levels();

        $this->assertSame('8.2.35', $l->targetFor('8.2.30'));
        $this->assertNull($l->targetFor('8.1.34'));
        $this->assertNull($l->targetFor(null));
    }

    public function test_daftar_tambalan_kosong_tidak_menandai_apa_pun_rentan(): void
    {
        $this->assertSame('safe', (new PhpPatchLevels([]))->classify('5.6.40'));
    }

    public function test_versi_dari_header_x_powered_by(): void
    {
        $found = PhpRuntimeScanner::fingerprint(['X-Powered-By' => ['PHP/5.6.40']]);

        $this->assertSame('5.6.40', $found['php_version']);
        $this->assertTrue($found['exposes_version']);
    }

    public function test_cookie_sesi_menandai_php_tanpa_versi(): void
    {
        foreach (['PHPSESSID=abc; path=/', 'simarkum_session=xyz; HttpOnly', 'ci_session=1', 'XSRF-TOKEN=t'] as $cookie) {
            $found = PhpRuntimeScanner::fingerprint(['set-cookie' => [$cookie]]);
            $this->assertNotNull($found, $cookie);
            $this->assertNull($found['php_version']);
            $this->assertSame('cookie', $found['detected_via']);
        }
    }

    public function test_wordpress_dikenali_dari_tautan_wp_json(): void
    {
        $found = PhpRuntimeScanner::fingerprint(['Link' => ['<https://x.ponorogo.go.id/wp-json/>; rel="https://api.w.org/"']]);

        $this->assertSame('wordpress', $found['detected_via']);
    }

    public function test_situs_bukan_php_tidak_dicatat(): void
    {
        $this->assertNull(PhpRuntimeScanner::fingerprint([
            'Server' => ['nginx'],
            'Set-Cookie' => ['cf_clearance=1; path=/', 'JSESSIONID=2'],
            'X-Powered-By' => ['Express'],
        ]));
    }

    /** Uptime Kuma (Node) dan WAGO (Go) di belakang Cloudflare Access, prod 23 Oktober 2026. */
    public function test_cookie_cloudflare_access_bukan_tanda_php(): void
    {
        $this->assertNull(PhpRuntimeScanner::fingerprint(['Set-Cookie' => [
            'CF_AppSession=343ece7c4d8bd5ab; Path=/; Secure; HttpOnly',
            'CF_Session=nIuLohNTm8ytVd6g9; Path=/; Secure; HttpOnly',
            '__cf_bm=abc; path=/',
        ]]));
    }

    /** kisara.ponorogo.go.id mengalihkan ke ponorogo.go.id: PHP tujuan bukan milik kisara. */
    public function test_redirect_hanya_diikuti_di_host_yang_sama(): void
    {
        $this->assertTrue(PhpRuntimeScanner::sameSite('https://espj.ponorogo.go.id/', 'https://espj.ponorogo.go.id/login'));
        $this->assertTrue(PhpRuntimeScanner::sameSite('https://ponorogo.go.id/', 'https://www.ponorogo.go.id/'));
        $this->assertFalse(PhpRuntimeScanner::sameSite('https://kisara.ponorogo.go.id/', 'https://ponorogo.go.id'));
        $this->assertFalse(PhpRuntimeScanner::sameSite('https://uptime.ponorogo.go.id/', 'https://kominfopng.cloudflareaccess.com/cdn-cgi/access/login/x'));
    }

    public function test_keluaran_whm_diurai_dan_vhost_bawaan_dibuang(): void
    {
        $output = "VER ea-php81 8.1.34\nVER ea-php83 8.3.36\n---VHOSTS---\n".json_encode(['data' => ['versions' => [
            ['vhost' => 'cutikom.ponorogo.go.id', 'version' => 'ea-php81'],
            ['vhost' => 'umum.ponorogo.go.id', 'version' => 'ea-php83'],
            ['vhost' => 'fe093dd2.cpx.local', 'version' => 'ea-php81'],
            ['vhost' => 'gentle-sapphire-walrus.103-109-206-29.cpanel.site', 'version' => 'ea-php81'],
            ['vhost' => 'lama.ponorogo.go.id', 'version' => 'ea-php74'],
        ]]]);

        $rows = PhpRuntimeScanner::parseWhm($output);

        $this->assertSame(['cutikom.ponorogo.go.id', 'umum.ponorogo.go.id', 'lama.ponorogo.go.id'], array_column($rows, 'vhost'));
        $this->assertSame('8.1.34', $rows[0]['php_version']);
        $this->assertSame('8.3.36', $rows[1]['php_version']);
        // Handler tanpa biner terpasang: versi tidak diketahui, bukan ditebak.
        $this->assertNull($rows[2]['php_version']);
    }

    public function test_keluaran_whm_rusak_menghasilkan_daftar_kosong(): void
    {
        $this->assertSame([], PhpRuntimeScanner::parseWhm('bash: whmapi1: command not found'));
    }
}
