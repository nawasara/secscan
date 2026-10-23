<?php

namespace Nawasara\Secscan\Livewire\PhpRuntimes;

use Livewire\Component;

/**
 * Versi PHP: shell only. Daftar, saringan, dan pindai ulang ada di
 * Section\Table.
 */
class Index extends Component
{
    public function render()
    {
        return view('nawasara-secscan::livewire.pages.php-runtimes.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
