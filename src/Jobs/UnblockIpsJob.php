<?php

namespace Nawasara\Secscan\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Services\IpBlockManager;

/**
 * Bulk unblock from the IP Blocks page ("Cabut hasil saringan").
 *
 * Queued because every block is one Cloudflare API call: hundreds of them
 * inside a Livewire request would time out half-way and leave the operator
 * not knowing which were lifted. Blocks are permanent by policy (decided 8
 * October 2026), so this is the only way old ones get cleaned up.
 */
class UnblockIpsJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * One job carries at most CHUNK blocks, about 60-90 s of work at the
     * pace below.
     * Laravel kills a job at the SMALLER of this and the worker --timeout, so
     * one job for 500 IPs would die half-way through.
     */
    public const CHUNK = 100;

    public int $timeout = 240;

    public int $tries = 1;

    /** @param  array<int,int>  $blockIds */
    public function __construct(public array $blockIds, public ?int $userId) {}

    public function handle(IpBlockManager $manager): void
    {
        $done = 0;
        $failed = 0;

        IpBlock::whereIn('id', $this->blockIds)->where('status', IpBlock::STATUS_ACTIVE)
            ->chunkById(50, function ($blocks) use ($manager, &$done, &$failed) {
                foreach ($blocks as $block) {
                    try {
                        $manager->unblock($block, $this->userId) ? $done++ : $failed++;
                    } catch (\Throwable $e) {
                        $failed++;
                        Log::warning('[secscan] bulk unblock failed for '.$block->ip.': '.$e->getMessage());
                    }

                    // Cloudflare's API allows ~1200 requests per 5 minutes; stay
                    // well under it so a big cleanup never trips the limit and
                    // fails the second half.
                    usleep(300_000);
                }
            });

        Log::info("[secscan] bulk unblock: {$done} dicabut, {$failed} gagal", ['user' => $this->userId]);
    }
}
