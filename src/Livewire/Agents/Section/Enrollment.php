<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\Computed;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Models\AgentEnrollmentToken;

/**
 * Token pendaftaran agen sekali pakai.
 *
 * Audit keamanan 15 Oktober 2026 (T1): POST /api/agent/register dulu terbuka
 * untuk siapa pun. Kini installer wajib membawa token dari sini. Token hanya
 * ditampilkan sekali, sesaat setelah dibuat; basis data hanya menyimpan
 * SHA-256-nya.
 *
 * Sudo saat membuat token: token ini adalah pintu masuk menjadi agen, dan
 * agen yang disetujui dapat memicu blokir IP di Cloudflare tingkat akun.
 */
class Enrollment extends Component
{
    use WithSudo;

    public string $label = '';

    public int $ttlHours = 24;

    // Token mentah, hanya ada di state komponen sampai modal ditutup.
    // #[Locked] supaya browser tidak dapat mengisinya sendiri.
    #[Locked]
    public ?string $issuedToken = null;

    public function mount(): void
    {
        $this->authorize('secscan.agent.enroll');
        $this->ttlHours = max(1, (int) config('nawasara-secscan.agent.enrollment_token_ttl_hours', 24));
    }

    /** @return array<int, string> */
    public function ttlOptions(): array
    {
        return [1 => '1 jam', 24 => '24 jam', 72 => '3 hari', 168 => '7 hari'];
    }

    #[Computed]
    public function tokens()
    {
        return AgentEnrollmentToken::with(['creator', 'agent'])
            ->orderByDesc('created_at')
            ->limit(10)
            ->get();
    }

    #[RequiresSudo(reason: 'membuat token pendaftaran agen keamanan')]
    public function issue(): void
    {
        $this->authorize('secscan.agent.enroll');

        $this->validate([
            'label' => 'nullable|string|max:100',
            'ttlHours' => 'required|integer|in:'.implode(',', array_keys($this->ttlOptions())),
        ], [], ['label' => 'Keterangan', 'ttlHours' => 'Masa berlaku']);

        [, $raw] = AgentEnrollmentToken::issue($this->label, $this->ttlHours, auth()->id());

        $this->issuedToken = $raw;
        $this->label = '';
        unset($this->tokens);

        $this->dispatch('modal-close:agent-enrollment-form');
        $this->dispatch('modal-open:agent-enrollment-result');
    }

    public function dismissToken(): void
    {
        $this->issuedToken = null;
        $this->dispatch('modal-close:agent-enrollment-result');
    }

    public function revokeToken(int $id): void
    {
        $this->authorize('secscan.agent.enroll');

        $token = AgentEnrollmentToken::findOrFail($id);

        if ($token->used_at === null && $token->revoked_at === null) {
            $token->forceFill(['revoked_at' => now(), 'revoked_by' => auth()->id()])->save();
        }

        unset($this->tokens);
        $this->dispatch('toast', type: 'success', message: 'Token pendaftaran dicabut.');
    }

    public function installCommand(): string
    {
        $url = rtrim((string) config('app.url'), '/');

        return 'curl -sSL '.$url.'/agent/install.sh | sudo NAWASARA_ENROLLMENT_TOKEN='.$this->issuedToken.' bash';
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.enrollment');
    }
}
