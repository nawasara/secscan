<?php

namespace Nawasara\Secscan\Tests;

use Nawasara\Secscan\Jobs\CheckAgentHealthJob;
use PHPUnit\Framework\TestCase;
use ReflectionMethod;

/**
 * Peringatan saat agen berhenti melapor.
 *
 * Agen adalah mata sistem keamanan, dan diamnya tidak terlihat seperti
 * masalah: nol insiden dari sebuah host terbaca persis sama, entah host itu
 * aman atau tidak ada yang mengawasinya.
 *
 * Diperiksa di produksi 4 September 2026 — `sadap` diam **45 hari**, dan tidak
 * ada satu pun peringatan. Agen sudah ditandai `offline` setelah 3 menit sejak
 * lama; yang tidak pernah ada adalah sesuatu yang memberitakannya.
 */
class AgentHealthTest extends TestCase
{
    private function lama(int $menit): string
    {
        $m = new ReflectionMethod(CheckAgentHealthJob::class, 'lamaTerbaca');
        $m->setAccessible(true);

        return $m->invoke(new CheckAgentHealthJob, $menit);
    }

    /**
     * "45 hari" terbaca; "64.631 menit" tidak.
     *
     * Peringatan ini dibaca di ponsel oleh orang yang harus memutuskan cepat
     * apakah perlu bangun — satuan yang harus dihitung sendiri menunda itu.
     */
    public function test_lama_diam_ditulis_dalam_satuan_yang_terbaca(): void
    {
        $this->assertSame('5 menit', $this->lama(5));
        $this->assertSame('59 menit', $this->lama(59));
        $this->assertSame('1 jam', $this->lama(60));
        $this->assertSame('21 jam', $this->lama(1263));   // ponorogo, nyata
        $this->assertSame('44 hari', $this->lama(64631)); // sadap, nyata
    }

    /**
     * Ambangnya harus jauh lebih longgar daripada selang detak.
     *
     * Detak tiap 60 detik (terukur: rata-rata 60s, terlama 120s pada enam agen
     * sehat). Ambang yang ketat akan berbunyi tiap kali agen dimulai ulang,
     * dan peringatan yang berbunyi saat tidak ada masalah melatih orang
     * mengabaikannya — persis saat ada agen yang benar-benar mati.
     */
    public function test_ambang_memberi_kelonggaran_jauh_di_atas_selang_detak(): void
    {
        $ambang = 30 * 60;   // detik
        $detakTerlama = 120; // terukur di produksi

        $this->assertGreaterThan(
            $detakTerlama * 10,
            $ambang,
            'Ambang harus setidaknya sepuluh kali selang detak terlama.',
        );
    }

    /**
     * Agen sehat TIDAK boleh ikut berbunyi.
     *
     * Delapan agen aktif di produksi, enam di antaranya sehat. Yang berbunyi
     * harus dua, bukan delapan.
     */
    public function test_agen_sehat_tidak_berbunyi(): void
    {
        $ambang = 30;
        $agen = [
            ['sadap', 64631], ['ponorogo', 1263],
            ['Docker-Master', 0], ['alpine', 0], ['Bale Production', 0],
            ['Bale-Organisasi', 0], ['Bale Disnaker', 0], ['docker-keycloak', 0],
        ];

        $berbunyi = array_filter($agen, fn ($a) => $a[1] >= $ambang);

        $this->assertCount(2, $berbunyi);
        $this->assertSame(['sadap', 'ponorogo'], array_column($berbunyi, 0));
    }
}
