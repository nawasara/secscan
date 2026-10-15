<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\Computed;
use Livewire\Attributes\On;
use Livewire\Attributes\Locked;
use Livewire\Component;
use Nawasara\AuthPrimitives\Attributes\RequiresSudo;
use Nawasara\AuthPrimitives\Traits\WithSudo;
use Nawasara\Secscan\Models\Agent;
use Nawasara\Secscan\Models\AgentCommand;
use Nawasara\Ui\Livewire\Concerns\HasExport;

class Commands extends Component
{
    use HasExport;
    use WithSudo;

    // #[Locked]: hanya diisi server (mount / openReject). Tanpa ini browser
    // dapat mengganti agentId di payload Livewire dan menerbitkan perintah ke
    // agen lain (audit keamanan 15 Oktober 2026).
    #[Locked]
    public string $agentId = '';

    // Issue command form
    public string $action = '';
    public string $paramIp = '';

    // Reject modal
    #[Locked]
    public ?int $rejectingId = null;
    public string $rejectionReason = '';

    public function mount(string $agentId): void
    {
        $this->agentId = $agentId;
        $this->authorize('secscan.agent.command');
    }

    /**
     * Penerbit perintah tidak boleh menyetujui perintahnya sendiri.
     *
     * Audit keamanan 15 Oktober 2026 (R7): tanpa ini, "butuh persetujuan"
     * untuk restart_mysql / block_ip hanya satu klik tambahan oleh orang yang
     * sama. Perintah tanpa created_by (perintah lama, perintah otomatis dari
     * Decision Engine) tidak terkena aturan ini.
     */
    public static function isSelfApproval(?int $createdBy, ?int $approverId): bool
    {
        return $createdBy !== null && $approverId !== null && $createdBy === $approverId;
    }

    #[Computed]
    public function agent(): Agent
    {
        return Agent::where('agent_id', $this->agentId)->firstOrFail();
    }

    #[Computed]
    public function commands()
    {
        return AgentCommand::where('agent_id', $this->agent->id)
            ->with(['createdBy', 'approvedBy', 'rejectedBy'])
            ->orderByDesc('created_at')
            ->limit(30)
            ->get();
    }

    #[Computed]
    public function pendingCount(): int
    {
        return AgentCommand::where('agent_id', $this->agent->id)
            ->where('status', AgentCommand::STATUS_PENDING)
            ->count();
    }

    public function issueCommand(): void
    {
        // Gate di setiap aksi, bukan hanya mount() (audit keamanan
        // 15 Oktober 2026, R7): izin dapat dicabut saat halaman masih
        // terbuka, dan aksi Livewire dapat dipanggil langsung.
        $this->authorize('secscan.agent.command');

        $this->validate([
            'action'   => 'required|in:block_ip,unblock_ip,restart_nginx,reload_nginx,restart_apache,reload_apache,restart_php_fpm,reload_php_fpm,restart_mysql,artisan_queue_restart,artisan_optimize_clear',
            'paramIp'  => 'nullable|ip',
        ]);

        $params = [];
        if (in_array($this->action, ['block_ip', 'unblock_ip'], true)) {
            $this->validate(['paramIp' => 'required|ip'], ['paramIp.required' => 'IP Address wajib diisi untuk aksi ini.']);
            $params['ip'] = $this->paramIp;
        }

        AgentCommand::create([
            'agent_id' => $this->agent->id,
            'action'   => $this->action,
            'params'     => $params ?: null,
            'status'     => AgentCommand::STATUS_PENDING,
            'created_by' => auth()->id(),
        ]);

        $this->reset('action', 'paramIp');
        $this->dispatch('command-issued');
        $this->dispatch('modal-close:modal-issue-command');

        session()->flash('flash.bannerStyle', 'success');
        session()->flash('flash.banner', 'Perintah dikirim, menunggu approval.');
    }

    #[RequiresSudo(reason: 'menyetujui perintah eksekusi pada agent')]
    public function approve(int $id): void
    {
        $this->authorize('secscan.agent.command.approve');

        $cmd = AgentCommand::where('id', $id)->where('agent_id', $this->agent->id)->firstOrFail();

        if (! $cmd->isPending()) {
            return;
        }

        if (! config('nawasara-secscan.agent.commands_allow_self_approve', false)
            && self::isSelfApproval($cmd->created_by, auth()->id())) {
            $this->dispatch('toast', type: 'error',
                message: 'Perintah yang Anda terbitkan sendiri harus disetujui admin lain.');

            return;
        }

        // Agen yang belum disetujui tidak mengambil perintah apa pun; menyetujui
        // perintahnya hanya menumpuk antrean yang tidak akan terkirim.
        if (! $this->agent->isApproved()) {
            $this->dispatch('toast', type: 'error', message: 'Agen ini belum disetujui.');

            return;
        }

        $cmd->update([
            'status'      => AgentCommand::STATUS_APPROVED,
            'approved_by' => auth()->id(),
            'approved_at' => now(),
        ]);

        $this->dispatch('command-approved');
        unset($this->commands);
        unset($this->pendingCount);
    }

    public function openReject(int $id): void
    {
        $this->authorize('secscan.agent.command');

        $this->rejectingId = $id;
        $this->rejectionReason = '';
        $this->dispatch('modal-open:modal-reject-command');
    }

    public function confirmReject(): void
    {
        // Menolak adalah arah yang aman (perintah tidak jalan), jadi cukup
        // izin menerbitkan; tetap diperiksa di sini, bukan hanya di mount().
        $this->authorize('secscan.agent.command');

        $this->validate(['rejectionReason' => 'required|string|min:5|max:500']);

        $cmd = AgentCommand::where('id', $this->rejectingId)
            ->where('agent_id', $this->agent->id)
            ->firstOrFail();

        if (! $cmd->isPending()) {
            $this->dispatch('modal-close:modal-reject-command');
            return;
        }

        $cmd->update([
            'status'           => AgentCommand::STATUS_REJECTED,
            'rejected_by'      => auth()->id(),
            'rejected_at'      => now(),
            'rejection_reason' => $this->rejectionReason,
        ]);

        $this->reset('rejectingId', 'rejectionReason');
        $this->dispatch('modal-close:modal-reject-command');
        unset($this->commands);
        unset($this->pendingCount);
    }

    #[On('command-issued')]
    #[On('command-approved')]
    public function refresh(): void
    {
        unset($this->commands);
        unset($this->pendingCount);
    }

    protected function exportFilename(): string
    {
        return 'secscan-commands-'.$this->agentId;
    }

    protected function exportData(): iterable
    {
        $this->authorize('secscan.export');

        return AgentCommand::where('agent_id', $this->agent->id)
            ->orderByDesc('created_at')
            ->get()
            ->map(fn (AgentCommand $c) => [
                'Command ID'  => $c->command_id,
                'Aksi'        => $c->actionLabel(),
                'Params'      => is_array($c->params) ? json_encode($c->params, JSON_UNESCAPED_SLASHES) : (string) $c->params,
                'Status'      => $c->statusLabel(),
                'Output'      => $c->output,
                'Error'       => $c->error,
                'Disetujui'   => $c->approved_at?->format('Y-m-d H:i:s'),
                'Ditolak'     => $c->rejected_at?->format('Y-m-d H:i:s'),
                'Alasan Tolak' => $c->rejection_reason,
                'Dieksekusi'  => $c->exec_at?->format('Y-m-d H:i:s'),
                'Dibuat'      => $c->created_at?->format('Y-m-d H:i:s'),
            ]);
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.agents.section.commands');
    }
}
