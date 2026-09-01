<?php

namespace Nawasara\Secscan\Tests;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;

/**
 * Normalisasi waktu dari agen ke UTC.
 *
 * Bug yang mendasarinya diam: agen mengirim RFC3339 lengkap dengan offsetnya
 * (`2026-09-02T04:40:05+07:00`) dan Carbon memarsingnya dengan BENAR — tetapi
 * objek hasilnya tetap membawa zona +07:00, dan Eloquent menuliskan JAM
 * DINDINGNYA apa adanya ke kolom datetime. Maka 04:40 WIB tersimpan sebagai
 * 04:40 UTC: tujuh jam di masa depan.
 *
 * Akibatnya di produksi: IP yang baru diblokir tampak masih menyerang tujuh
 * jam kemudian, dan insiden pemicu sebuah blokir tercatat SESUDAH blokir yang
 * disebabkannya. Tidak ada yang terlihat rusak — tidak ada galat, tidak ada
 * baris gagal — sehingga dugaan pertama tertuju pada Cloudflare yang bocor.
 *
 * Yang diuji di sini adalah jam yang TERSIMPAN, bukan hasil parsing. Parsingnya
 * memang tidak pernah salah, dan itulah yang membuat bug ini bertahan lama.
 */
class AgentTimestampTest extends TestCase
{
    /** Jam dinding WIB harus tersimpan sebagai UTC, mundur tujuh jam. */
    public function test_waktu_agen_dinormalkan_ke_utc(): void
    {
        $detected = Carbon::parse('2026-09-02T04:40:05+07:00')->utc();

        $this->assertSame('2026-09-01 21:40:05', $detected->toDateTimeString());
        $this->assertSame('UTC', $detected->timezoneName);
    }

    /**
     * Tanpa ->utc(), yang tersimpan adalah jam dinding — inti bugnya.
     *
     * Uji ini sengaja memperagakan perilaku yang SALAH, supaya alasan
     * pemanggilan ->utc() tetap terbaca meski kelak dianggap berlebihan.
     */
    public function test_tanpa_utc_jam_dinding_ikut_tersimpan(): void
    {
        $salah = Carbon::parse('2026-09-02T04:40:05+07:00');

        // Parsingnya benar — inilah sebabnya bug ini sulit terlihat:
        // saat yang ditunjuk memang sama persis dengan versi UTC-nya.
        $this->assertSame(
            Carbon::parse('2026-09-01T21:40:05Z')->getTimestamp(),
            $salah->getTimestamp(),
        );

        // Tetapi jam dindingnya masih WIB, dan itu yang ditulis Eloquent.
        $this->assertSame('2026-09-02 04:40:05', $salah->toDateTimeString());

        $selisih = $salah->toDateTimeString() === $salah->copy()->utc()->toDateTimeString();
        $this->assertFalse($selisih, 'Jam dinding WIB dan UTC tidak boleh dianggap sama.');
    }

    /** Agen yang sudah mengirim UTC tidak boleh ikut tergeser. */
    public function test_waktu_yang_sudah_utc_tidak_berubah(): void
    {
        foreach (['2026-09-01T21:40:05Z', '2026-09-01T21:40:05+00:00'] as $input) {
            $this->assertSame(
                '2026-09-01 21:40:05',
                Carbon::parse($input)->utc()->toDateTimeString(),
                "Input $input seharusnya tidak bergeser."
            );
        }
    }

    /**
     * Insiden tidak boleh tercatat SESUDAH blokir yang disebabkannya.
     *
     * Inilah gejala yang dilaporkan pengguna — "IP sudah diblokir tapi masih
     * menyerang". Angkanya diambil dari baris produksi yang sungguh terjadi.
     */
    public function test_insiden_pemicu_tidak_mendahului_blokirnya(): void
    {
        $blocked = Carbon::parse('2026-09-01 20:02:38', 'UTC');   // dicatat Laravel
        $detected = Carbon::parse('2026-09-02T03:01:33+07:00')->utc();

        $this->assertTrue(
            $detected->lessThanOrEqualTo($blocked),
            'Insiden pemicu harus terjadi SEBELUM blokirnya, bukan sesudah.'
        );
    }
}
