<?php

namespace Nawasara\Secscan\Tests;

use Nawasara\Secscan\Services\WpInspector;
use Nawasara\Secscan\Support\OutboundUrlGuard;
use PHPUnit\Framework\TestCase;

/**
 * Penjaga SSRF pemindai HTTP (audit keamanan 15 Oktober 2026, R10) dan
 * pembentukan tautan dari opsi `home` WordPress (R13).
 *
 * Situs OPD yang disusupi dapat menjawab dengan redirect ke jaringan dalam.
 * Setiap alamat di bawah ini pernah atau mungkin dipakai untuk itu.
 */
class OutboundUrlGuardTest extends TestCase
{
    public function test_alamat_dalam_dan_khusus_ditolak(): void
    {
        foreach ([
            '127.0.0.1', '127.8.8.8', '10.1.1.23', '172.16.0.1', '172.31.255.255',
            '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
            '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', '::ffff:127.0.0.1',
            '224.0.0.1', 'bukan-ip',
        ] as $ip) {
            $this->assertFalse(OutboundUrlGuard::isPublicIp($ip), $ip.' seharusnya ditolak');
        }
    }

    public function test_alamat_publik_diterima(): void
    {
        foreach (['103.109.206.10', '1.1.1.1', '104.16.0.1', '2606:4700::6810:84e5'] as $ip) {
            $this->assertTrue(OutboundUrlGuard::isPublicIp($ip), $ip.' seharusnya diterima');
        }
    }

    public function test_skema_selain_http_https_ditolak(): void
    {
        $resolver = fn () => ['1.1.1.1'];

        foreach (['file:///etc/passwd', 'gopher://x.ponorogo.go.id/', 'javascript:alert(1)', 'ftp://1.1.1.1/'] as $url) {
            $this->assertFalse(OutboundUrlGuard::check($url, $resolver)['ok'], $url);
        }

        $this->assertTrue(OutboundUrlGuard::check('https://dinkes.ponorogo.go.id/', $resolver)['ok']);
    }

    public function test_host_yang_resolve_ke_ip_dalam_ditolak(): void
    {
        // Satu saja alamat dalam cukup untuk menolak: curl bebas memilih.
        $mixed = fn () => ['1.1.1.1', '10.0.0.5'];
        $this->assertFalse(OutboundUrlGuard::check('http://jahat.example/', $mixed)['ok']);

        $this->assertFalse(OutboundUrlGuard::check('http://169.254.169.254/latest/meta-data')['ok']);
        $this->assertFalse(OutboundUrlGuard::check('http://[::1]:8080/')['ok']);
        $this->assertFalse(OutboundUrlGuard::check('http://x.example/', fn () => [])['ok']);
    }

    public function test_userinfo_ditolak(): void
    {
        $this->assertFalse(OutboundUrlGuard::check('http://user:pass@1.1.1.1/')['ok']);
    }

    public function test_hasil_check_membawa_ip_untuk_disematkan(): void
    {
        $r = OutboundUrlGuard::check('https://situs.example:8443/a', fn () => ['8.8.8.8']);

        $this->assertTrue($r['ok']);
        $this->assertSame('situs.example', $r['host']);
        $this->assertSame(8443, $r['port']);
        $this->assertSame('8.8.8.8', $r['ip']);
    }

    public function test_location_relatif_dijadikan_absolut(): void
    {
        $base = 'https://a.ponorogo.go.id/dir/page?x=1';

        $this->assertSame('https://a.ponorogo.go.id/login', OutboundUrlGuard::absolutize('/login', $base));
        $this->assertSame('https://b.example/x', OutboundUrlGuard::absolutize('//b.example/x', $base));
        $this->assertSame('https://a.ponorogo.go.id/dir/next', OutboundUrlGuard::absolutize('next', $base));
        $this->assertSame('http://10.0.0.1/', OutboundUrlGuard::absolutize('http://10.0.0.1/', $base));
    }

    public function test_home_wordpress_hanya_http_https(): void
    {
        $this->assertSame('https://desa.ponorogo.go.id', WpInspector::safeBaseUrl('https://desa.ponorogo.go.id/'));
        $this->assertSame('http://desa.ponorogo.go.id/wp', WpInspector::safeBaseUrl('http://desa.ponorogo.go.id/wp'));

        foreach (['javascript:alert(1)', 'JavaScript://x.example/%0aalert(1)', 'data:text/html,x', '//x.example',
            'https://x.example/"onmouseover=alert(1)', '', 'vbscript:x'] as $home) {
            $this->assertSame('', WpInspector::safeBaseUrl($home), $home);
        }
    }
}
