<?php

namespace Nawasara\Secscan\Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class PermissionSeeder extends Seeder
{
    public function run(): void
    {
        $permissions = [
            'secscan.view',            // dashboard + findings + agents list
            'secscan.finding.triage',  // acknowledge / false-positive / resolve
            'secscan.scan.execute',    // trigger a manual rescan
            'secscan.agent.view',      // view agent detail + incidents
            'secscan.agent.delete',    // remove/revoke agent registration
            'secscan.agent.command',   // issue + reject remote commands (Phase 2)
            // Audit keamanan 15 Oktober 2026 (R7): menyetujui perintah dipisah
            // dari menerbitkannya, supaya peran yang boleh mengusulkan
            // restart_mysql / block_ip tidak otomatis boleh mengeksekusinya.
            'secscan.agent.command.approve',
            // Audit keamanan 15 Oktober 2026 (T1): membuat token pendaftaran
            // agen dan menyetujui agen baru. Agen yang disetujui dapat memicu
            // blokir IP di Cloudflare, jadi ini izin tersendiri.
            'secscan.agent.enroll',
            'secscan.agent.scan',      // triage file scanner findings (Phase 3)
            'secscan.export',          // export any secscan table (csv/xlsx/json)
            'secscan.ip-block.manage', // view IP blocks + manual unblock (Decision Engine)
            'secscan.settings.manage', // notification settings (digest + alert recipients)
        ];

        foreach ($permissions as $permission) {
            Permission::firstOrCreate(['name' => $permission, 'guard_name' => 'web']);
        }

        // All three are read-/triage-only (no destructive action against OPD
        // data), so granting the full set to developer is safe here.
        $role = Role::where('name', 'developer')->first();
        $role?->givePermissionTo($permissions);
    }
}
