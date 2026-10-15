<?php

namespace Nawasara\Secscan\Tests;

use Illuminate\Support\Carbon;
use Nawasara\Secscan\Livewire\Agents\Section\Commands;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentEnrollmentToken;
use Nawasara\Secscan\Services\DecisionEngine;
use PHPUnit\Framework\TestCase;

/**
 * Pendaftaran dan persetujuan agen (audit keamanan 15 Oktober 2026, T1),
 * serta aturan "tidak menyetujui perintah sendiri" (R7).
 *
 * Sebelumnya siapa pun di internet dapat mendaftarkan agen lalu membuat
 * Decision Engine memblokir IP sembarang di Cloudflare tingkat akun.
 */
class AgentEnrollmentTest extends TestCase
{
    /** Model tanpa koneksi basis data: format tanggal ditetapkan sendiri. */
    private function token(array $attrs): AgentEnrollmentToken
    {
        $t = new class extends AgentEnrollmentToken {
            protected $dateFormat = 'Y-m-d H:i:s';
        };

        return $t->forceFill($attrs);
    }

    private function agent(array $attrs): Agent
    {
        $a = new class extends Agent {
            protected $dateFormat = 'Y-m-d H:i:s';
        };

        return $a->forceFill($attrs);
    }

    public function test_token_baru_dapat_dipakai_sebelum_kedaluwarsa(): void
    {
        $now = Carbon::parse('2026-10-15 10:00:00');
        $t = $this->token(['expires_at' => $now->copy()->addHours(24)]);

        $this->assertTrue($t->isUsableAt($now));
        $this->assertFalse($t->isUsableAt($now->copy()->addHours(25)));
    }

    public function test_token_terpakai_atau_dicabut_tidak_dapat_dipakai_lagi(): void
    {
        $now = Carbon::parse('2026-10-15 10:00:00');
        $exp = $now->copy()->addDay();

        $this->assertFalse($this->token(['expires_at' => $exp, 'used_at' => $now])->isUsableAt($now));
        $this->assertFalse($this->token(['expires_at' => $exp, 'revoked_at' => $now])->isUsableAt($now));
        $this->assertFalse($this->token([])->isUsableAt($now), 'tanpa expires_at tidak boleh dianggap berlaku');
    }

    public function test_token_acak_berprefiks_dan_hash_stabil(): void
    {
        $a = AgentEnrollmentToken::generateRaw();
        $b = AgentEnrollmentToken::generateRaw();

        $this->assertStringStartsWith('nwe_', $a);
        $this->assertSame(52, strlen($a)); // nwe_ + 48 hex (192 bit)
        $this->assertNotSame($a, $b);
        $this->assertSame(AgentEnrollmentToken::hashToken($a), AgentEnrollmentToken::hashToken(" {$a}\n"));
        $this->assertSame(64, strlen(AgentEnrollmentToken::hashToken($a)));
    }

    public function test_hanya_agen_disetujui_dan_belum_dicabut_yang_dipercaya(): void
    {
        $this->assertTrue($this->agent(['approval_status' => 'approved'])->isApproved());
        $this->assertFalse($this->agent(['approval_status' => 'pending'])->isApproved());
        $this->assertFalse($this->agent([])->isApproved(), 'status kosong jatuh ke keadaan aman');
        $this->assertFalse($this->agent([
            'approval_status' => 'approved',
            'deleted_at' => Carbon::parse('2026-10-01'),
        ])->isApproved(), 'agen yang dicabut tidak boleh memicu blokir');
    }

    public function test_batas_blokir_per_agen(): void
    {
        $this->assertFalse(DecisionEngine::capReached(29, 30));
        $this->assertTrue(DecisionEngine::capReached(30, 30));
        $this->assertFalse(DecisionEngine::capReached(1000, 0), '0 berarti tanpa batas');
    }

    public function test_penerbit_tidak_dapat_menyetujui_perintahnya_sendiri(): void
    {
        $this->assertTrue(Commands::isSelfApproval(7, 7));
        $this->assertFalse(Commands::isSelfApproval(7, 8));
        // Perintah lama dan perintah otomatis Decision Engine tidak punya penerbit.
        $this->assertFalse(Commands::isSelfApproval(null, 7));
    }
}
