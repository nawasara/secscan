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
            'secscan.agent.command',   // issue + approve/reject remote commands (Phase 2)
            'secscan.agent.scan',      // triage file scanner findings (Phase 3)
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
