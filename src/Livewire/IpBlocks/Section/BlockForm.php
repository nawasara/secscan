<?php

namespace Nawasara\Secscan\Livewire\IpBlocks\Section;

use Livewire\Component;
use Nawasara\Secscan\Services\IpBlockManager;

/**
 * Manual block. Until now the panel could only lift blocks; blocking an IP
 * staff had spotted themselves meant waiting for the Decision Engine or
 * calling the API with a token.
 */
class BlockForm extends Component
{
    public string $ip = '';

    public string $reason = '';

    public function save(IpBlockManager $manager): void
    {
        $this->authorize('secscan.ip-block.manage');

        $data = $this->validate([
            'ip' => ['required', 'ip'],
            'reason' => ['required', 'string', 'max:64'],
        ], [], ['ip' => 'IP', 'reason' => 'alasan']);

        $result = $manager->block(trim($data['ip']), trim($data['reason']), 'panel', auth()->id());

        if ($result['error'] !== null) {
            $this->addError('ip', str_starts_with($result['error'], IpBlockManager::ERROR_WHITELISTED)
                ? 'IP ini masuk daftar putih (kantor, Cloudflare, atau mesin pencari) dan tidak boleh diblokir.'
                : 'Cloudflare menolak membuat aturannya. IP belum diblokir; coba lagi.');

            return;
        }

        $this->reset('ip', 'reason');
        $this->dispatch('modal-close:ip-block-form');
        $this->dispatch('ip-block-saved');
        $this->dispatch('toast', type: 'success', message: $result['existing']
            ? 'IP ini memang sudah diblokir.'
            : 'IP '.$result['block']->ip.' diblokir.');
    }

    public function render()
    {
        return view('nawasara-secscan::livewire.pages.ip-blocks.section.block-form');
    }
}
