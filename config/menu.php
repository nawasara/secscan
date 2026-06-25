<?php

$prefix = 'nawasara-secscan';

return [
    [
        'workspace' => 'security',
        'label' => 'Keamanan',
        'icon' => 'lucide-shield-alert',
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
                'label' => 'Temuan',
                'icon' => 'lucide-bug',
                'url' => url($prefix.'/findings'),
                'permission' => 'secscan.view',
                'navigate' => true,
            ],
        ],
    ],
];
