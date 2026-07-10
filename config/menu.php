<?php

$prefix = 'nawasara-secscan';

return [
    [
        'workspace' => 'security',
        'label' => 'Keamanan',
        'icon' => 'lucide-shield-alert',
        'group' => 'Keamanan',
        'url' => '',
        'permission' => 'secscan.view',
        'submenu' => [
            [
                'label' => 'Dashboard',
                'icon' => 'lucide-layout-dashboard',
                'url' => url($prefix.'/dashboard'),
                'permission' => 'secscan.view',
                'navigate' => true,
            ],
            [
                'label' => 'Temuan Website',
                'icon' => 'lucide-bug',
                'url' => url($prefix.'/findings'),
                'permission' => 'secscan.view',
                'navigate' => true,
            ],
            [
                'label' => 'Incidents',
                'icon' => 'lucide-siren',
                'url' => url($prefix.'/incidents'),
                'permission' => 'secscan.view',
                'navigate' => true,
            ],
            [
                'label' => 'Agents',
                'icon' => 'lucide-server',
                'url' => url($prefix.'/agents'),
                'permission' => 'secscan.view',
                'navigate' => true,
            ],
            [
                'label' => 'IP Blocks',
                'icon' => 'lucide-shield-ban',
                'url' => url($prefix.'/ip-blocks'),
                'permission' => 'secscan.ip-block.manage',
                'navigate' => true,
            ],
        ],
    ],
];
