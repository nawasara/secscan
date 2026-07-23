<?php

namespace Nawasara\Secscan\Http\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Nawasara\Secscan\Http\Resources\IpBlockResource;
use Nawasara\Secscan\Models\IpBlock;
use Nawasara\Secscan\Services\CloudflareBlockService;

/**
 * Public API untuk IP blocking di Cloudflare edge.
 *
 * Auth + scope sudah di-cek di middleware sebelum controller jalan:
 *   - api.auth  → token valid + aktif
 *   - scope:secscan.ipblock.read   → index + show
 *   - scope:secscan.ipblock.write  → store (block)
 *   - scope:secscan.ipblock.delete → destroy (unblock)
 *
 * Write & delete SENGAJA memakai CloudflareBlockService + IpBlock yang sama
 * dengan Decision Engine (auto-block). Konsekuensinya: block via API muncul di
 * dashboard IP Blocks, ter-audit lewat api.log, dan menghormati flag dry_run
 * global — sebuah token API tidak bisa dipakai mem-bypass mode dry-run.
 */
class IpBlockController extends Controller
{
    public function __construct(protected CloudflareBlockService $blocker)
    {
    }

    /**
     * GET /api/v1/secscan/ip-blocks
     * Scope: secscan.ipblock.read
     *
     * Daftar IP block. Default hanya yang aktif; ?status=all|removed untuk
     * riwayat. ?q=1.2.3 untuk cari prefix IP.
     */
    public function index(Request $request): JsonResponse
    {
        $query = IpBlock::query()->latest('blocked_at');

        $status = (string) $request->query('status', 'active');
        if ($status === 'active') {
            $query->where('status', IpBlock::STATUS_ACTIVE);
        } elseif ($status === 'removed') {
            $query->where('status', IpBlock::STATUS_REMOVED);
        }
        // status=all → tanpa filter.

        if ($q = trim((string) $request->query('q', ''))) {
            $query->where('ip', 'like', $q.'%');
        }

        $perPage = min(100, max(1, (int) $request->query('per_page', 50)));
        $blocks = $query->paginate($perPage);

        return response()->json([
            'data' => IpBlockResource::collection($blocks->items())->resolve(),
            'meta' => [
                'total'        => $blocks->total(),
                'per_page'     => $blocks->perPage(),
                'current_page' => $blocks->currentPage(),
                'last_page'    => $blocks->lastPage(),
            ],
        ]);
    }

    /**
     * GET /api/v1/secscan/ip-blocks/{ip}
     * Scope: secscan.ipblock.read
     *
     * Detail block terbaru untuk satu IP (aktif diutamakan).
     */
    public function show(string $ip): JsonResponse
    {
        $block = IpBlock::where('ip', $ip)
            ->orderByRaw("status = '".IpBlock::STATUS_ACTIVE."' desc")
            ->latest('blocked_at')
            ->first();

        if (! $block) {
            return response()->json([
                'error'   => 'not_found',
                'message' => 'Tidak ada catatan block untuk IP ini.',
            ], 404);
        }

        return response()->json(['data' => (new IpBlockResource($block))->resolve()]);
    }

    /**
     * POST /api/v1/secscan/ip-blocks
     * Scope: secscan.ipblock.write
     *
     * Body: { "ip": "1.2.3.4", "reason": "manual via api" }
     *
     * Block IP di Cloudflare. Idempoten: kalau IP sudah aktif ter-block,
     * kembalikan record yang ada (200) alih-alih membuat duplikat.
     */
    public function store(Request $request): JsonResponse
    {
        $data = $request->validate([
            'ip'     => ['required', 'string', 'ip'],
            'reason' => ['nullable', 'string', 'max:64'],
        ]);

        $ip = $data['ip'];

        // Gate whitelist — SAMA dengan Decision Engine (fail-safe). Tanpa ini,
        // sebuah token API bisa dipakai (sengaja atau tidak) mem-block IP kantor
        // sendiri, range Cloudflare, atau search bot. Tolak di sini.
        $wl = \Nawasara\Secscan\Support\IpWhitelist::check($ip);
        if ($wl['whitelisted']) {
            return response()->json([
                'error'   => 'whitelisted',
                'message' => 'IP ini di-whitelist ('.$wl['reason'].') dan tidak boleh di-block.',
            ], 422);
        }

        // Idempoten — jangan double-block.
        if ($existing = IpBlock::active()->where('ip', $ip)->first()) {
            return response()->json([
                'data'    => (new IpBlockResource($existing))->resolve(),
                'message' => 'IP sudah ter-block.',
            ], 200);
        }

        $dryRun = (bool) config('nawasara-secscan.autoblock.dry_run', true);
        $prefix = (string) config('nawasara-secscan.autoblock.notes_prefix', 'nawasara-autoblock');
        $reason = $data['reason'] ?? 'manual-api';
        $notes  = sprintf('%s:api ip=%s reason=%s by=token#%s', $prefix, $ip, $reason, $this->tokenId($request) ?? '?');

        // Push ke Cloudflare hanya kalau bukan dry-run. Sama persis dengan
        // Decision Engine — token API tidak bisa mem-bypass dry-run global.
        $cfRuleId = null;
        if (! $dryRun) {
            $cfRuleId = $this->blocker->block($ip, $notes);
            if (! $cfRuleId) {
                Log::warning('[secscan] API block failed at Cloudflare', ['ip' => $ip]);

                return response()->json([
                    'error'   => 'cloudflare_error',
                    'message' => 'Gagal membuat rule di Cloudflare. IP tidak ter-block.',
                ], 502);
            }
        }

        $block = IpBlock::create([
            'ip'          => $ip,
            'status'      => IpBlock::STATUS_ACTIVE,
            'reason'      => $reason,
            'cf_rule_id'  => $cfRuleId,
            'incident_id' => null,
            'dry_run'     => $dryRun,
            'notes'       => $notes,
            'blocked_by'  => $this->userId($request),
            'blocked_at'  => now(),
        ]);

        Log::info('[secscan] API '.($dryRun ? 'WOULD block (dry-run)' : 'BLOCKED').' '.$ip, [
            'reason' => $reason, 'cf_rule' => $cfRuleId, 'token' => $this->tokenId($request),
        ]);

        return response()->json([
            'data'    => (new IpBlockResource($block))->resolve(),
            'message' => $dryRun ? 'Dry-run: block dicatat tapi TIDAK di-push ke Cloudflare.' : 'IP ter-block di Cloudflare.',
        ], 201);
    }

    /**
     * DELETE /api/v1/secscan/ip-blocks/{ip}
     * Scope: secscan.ipblock.delete
     *
     * Buka blokir. Menghapus rule di Cloudflare (kalau ada) lalu menandai
     * record sebagai removed.
     */
    public function destroy(Request $request, string $ip): JsonResponse
    {
        $block = IpBlock::active()->where('ip', $ip)->latest('blocked_at')->first();

        if (! $block) {
            return response()->json([
                'error'   => 'not_found',
                'message' => 'Tidak ada block aktif untuk IP ini.',
            ], 404);
        }

        // Hapus rule di CF kalau benar-benar ada (bukan dry-run tanpa rule id).
        if ($block->cf_rule_id) {
            $ok = $this->blocker->unblock($block->cf_rule_id);
            if (! $ok) {
                Log::warning('[secscan] API unblock: Cloudflare delete failed', ['ip' => $ip, 'rule' => $block->cf_rule_id]);

                return response()->json([
                    'error'   => 'cloudflare_error',
                    'message' => 'Gagal menghapus rule di Cloudflare. Block belum dibuka.',
                ], 502);
            }
        }

        $block->update([
            'status'       => IpBlock::STATUS_REMOVED,
            'unblocked_by' => $this->userId($request),
            'unblocked_at' => now(),
        ]);

        Log::info('[secscan] API unblocked '.$ip, ['token' => $this->tokenId($request)]);

        return response()->json([
            'data'    => (new IpBlockResource($block->fresh()))->resolve(),
            'message' => 'Block dibuka.',
        ]);
    }

    /**
     * User yang di-attribut-kan ke block ini (kolom blocked_by/unblocked_by).
     * ApiToken tidak punya kolom user_id — yang ada `created_by` (pembuat
     * token). Itu yang paling dekat dengan "siapa di balik aksi ini". Null
     * aman: FK blocked_by nullable.
     */
    protected function userId(Request $request): ?int
    {
        $token = $request->attributes->get('api_token');

        return $token?->created_by;
    }

    protected function tokenId(Request $request): ?int
    {
        $token = $request->attributes->get('api_token');

        return $token?->id;
    }
}
