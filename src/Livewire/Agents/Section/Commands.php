<?php

namespace Nawasara\Secscan\Livewire\Agents\Section;

use Livewire\Attributes\Computed;
use Livewire\Attributes\On;
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

    public string $agentId = '';

    // Issue command form
    public string $action = '';
    public string $paramIp = '';

    // Reject modal
    public ?int $rejectingId = null;
    public string $rejectionReason = '';

    public function mount(string $agentId): void
    {
        $this->agentId = $agentId;
        $this->authorize('secscan.agent.command');
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
            'params'   => $params ?: null,
            'status'   => AgentCommand::STATUS_PENDING,
        ]);

        $this->reset('action', 'paramIp');
        $this->dispatch('command-issued');
        $this->dispatch('close-modal', 'modal-issue-command');

        session()->flash('flash.bannerStyle', 'success');
        session()->flash('flash.banner', 'Perintah dikirim, menunggu approval.');
    }

    #[RequiresSudo(reason: 'menyetujui perintah eksekusi pada agent')]
    public function approve(int $id): void
    {
        $cmd = AgentCommand::where('id', $id)->where('agent_id', $this->agent->id)->firstOrFail();

        if (! $cmd->isPending()) {
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
        $this->rejectingId = $id;
        $this->rejectionReason = '';
        $this->dispatch('modal-open:modal-reject-command');
    }

    public function confirmReject(): void
    {
        $this->validate(['rejectionReason' => 'required|string|min:5|max:500']);

        $cmd = AgentCommand::where('id', $this->rejectingId)
            ->where('agent_id', $this->agent->id)
            ->firstOrFail();

        if (! $cmd->isPending()) {
            $this->dispatch('modal-open:modal-reject-command');
            return;
        }

        $cmd->update([
            'status'           => AgentCommand::STATUS_REJECTED,
            'rejected_by'      => auth()->id(),
            'rejected_at'      => now(),
            'rejection_reason' => $this->rejectionReason,
        ]);

        $this->reset('rejectingId', 'rejectionReason');
        $this->dispatch('modal-open:modal-reject-command');
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
