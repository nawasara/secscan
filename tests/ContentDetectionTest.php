<?php

namespace Nawasara\Secscan\Tests;

use Nawasara\Secscan\Jobs\ScanHttpJob;
use Nawasara\Secscan\Services\FileFindingAlerts;
use Nawasara\Secscan\Services\SitemapProbe;
use Nawasara\Secscan\Support\VolatilePath;
use PHPUnit\Framework\TestCase;

/**
 * Coverage gaps found tracing SLOT777 on umum.ponorogo.go.id (16 Oct 2026):
 * file findings never alerted, integrity noise buried real ones, and the HTTP
 * probe read only the homepage as Googlebot.
 */
class ContentDetectionTest extends TestCase
{
    public function test_file_alert_rules_by_category(): void
    {
        $this->assertSame(FileFindingAlerts::RULE_SPAM, FileFindingAlerts::ruleFor('seo_spam'));
        $this->assertSame(FileFindingAlerts::RULE_MALICIOUS, FileFindingAlerts::ruleFor('webshell'));
        $this->assertSame(FileFindingAlerts::RULE_MALICIOUS, FileFindingAlerts::ruleFor('backdoor'));
        $this->assertNull(FileFindingAlerts::ruleFor('integrity'), 'integrity must never alert');
        $this->assertNull(FileFindingAlerts::ruleFor('suspicious'));
    }

    public function test_site_root_groups_files_of_one_account(): void
    {
        $this->assertSame('/home/jambonponorogogo', FileFindingAlerts::siteRoot('/home/jambonponorogogo/public_html/hitam.html'));
        $this->assertSame('/home/jambonponorogogo', FileFindingAlerts::siteRoot('/home/jambonponorogogo/public_html/wp-content/themes/today/x.html'));
        $this->assertSame('/var/www/umum', FileFindingAlerts::siteRoot('/var/www/umum/public/index.php'));
        $this->assertSame('/srv/app', FileFindingAlerts::siteRoot('/srv/app/public/x.php'));
        $this->assertSame('5:/home/a', FileFindingAlerts::targetId(5, '/home/a'));
    }

    public function test_volatile_paths_skip_integrity_only(): void
    {
        $this->assertTrue(VolatilePath::matches('/home/pertanianponorog/public_html/wp-content/cache/supercache/x/index-https.html'));
        $this->assertTrue(VolatilePath::matches('/home/siimutponorogogo/public_html/application/user/logs/log-2026-10-16.php'));
        $this->assertTrue(VolatilePath::matches('/var/www/app/storage/framework/views/abc.php'));

        $this->assertFalse(VolatilePath::matches('/home/jambonponorogogo/public_html/hitam.html'));
        $this->assertFalse(VolatilePath::matches('/home/x/public_html/wp-config.php'));
        $this->assertFalse(VolatilePath::matches('/home/x/public_html/wp-content/themes/today/index.php'));
    }

    public function test_sitemap_slugs_flag_gambling_but_not_government_words(): void
    {
        $kw = ['gacor', 'maxwin', 'obat aborsi'];

        $this->assertSame(['gacor'], SitemapProbe::slugKeywords('/2026/10/situs-slot-gacor-hari-ini/', $kw));
        $this->assertContains('slot777', SitemapProbe::slugKeywords('/info/slot777-login/', $kw));
        $this->assertSame(['obat aborsi'], SitemapProbe::slugKeywords('/jual-obat-aborsi-ponorogo', $kw));

        $this->assertSame([], SitemapProbe::slugKeywords('/berita/slot-anggaran-2026/', $kw), 'bare "slot" is not gambling');
        $this->assertSame([], SitemapProbe::slugKeywords('/berita/bahaya-judi-online-bagi-remaja/', $kw));
    }

    public function test_sitemap_parsing_reads_loc_and_lastmod(): void
    {
        $xml = '<urlset><url><loc>https://a.ponorogo.go.id/x/</loc><lastmod>2026-10-01</lastmod></url>'
            .'<url><loc>https://a.ponorogo.go.id/y/?p=1&amp;q=2</loc></url></urlset>';

        $locs = SitemapProbe::parseLocs($xml);

        $this->assertCount(2, $locs);
        $this->assertSame('2026-10-01', $locs[0]['lastmod']);
        $this->assertSame('https://a.ponorogo.go.id/y/?p=1&q=2', $locs[1]['loc']);
        $this->assertNull($locs[1]['lastmod']);
    }

    public function test_signal_seen_by_one_visitor_only_is_cloaking(): void
    {
        $judol = ['threat_type' => 'judol', 'score' => 80, 'evidence' => ['url' => 'u']];

        $merged = ScanHttpJob::mergeVariants(
            ['scanned' => true, 'signals' => []],
            ['scanned' => true, 'signals' => [$judol]],
        );

        $this->assertCount(1, $merged);
        $this->assertSame('mobile_google', $merged[0]['evidence']['cloaking']);
        $this->assertSame(['mobile_google'], $merged[0]['evidence']['variants']);
    }

    public function test_signal_seen_by_both_keeps_higher_score_without_cloaking_tag(): void
    {
        $merged = ScanHttpJob::mergeVariants(
            ['scanned' => true, 'signals' => [['threat_type' => 'judol', 'score' => 60, 'evidence' => []]]],
            ['scanned' => true, 'signals' => [['threat_type' => 'judol', 'score' => 90, 'evidence' => []]]],
        );

        $this->assertSame(90, $merged[0]['score']);
        $this->assertArrayNotHasKey('cloaking', $merged[0]['evidence']);
    }

    public function test_failed_second_fetch_is_not_reported_as_cloaking(): void
    {
        $merged = ScanHttpJob::mergeVariants(
            ['scanned' => true, 'signals' => [['threat_type' => 'judol', 'score' => 80, 'evidence' => []]]],
            ['scanned' => false, 'signals' => []],
        );

        $this->assertArrayNotHasKey('cloaking', $merged[0]['evidence']);
    }
}
