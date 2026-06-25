<?php

namespace Nawasara\Secscan\Services;

use Nawasara\Secscan\Models\SecscanFinding;

/**
 * Turns the raw signals gathered by SqlSignalDetector into scored findings.
 *
 * Philosophy (lesson from hibah DuplicateDetector: 1769 FP → 8 real): strong
 * signals can stand alone and push severity to critical; weak signals only
 * nudge the score and never alert on their own. A finding is grouped by
 * threat_type so one site can have e.g. both a 'judol' and a 'malware' row.
 */
class FindingScorer
{
    /**
     * @param  array<string,mixed>  $signals  output of SqlSignalDetector::collect()
     * @return list<array{threat_type:string, score:int, severity:string, evidence:array}>
     */
    public function score(array $signals): array
    {
        $findings = [];

        // ---- JUDOL (gambling SEO spam) -------------------------------------
        $judolScore = 0;
        $judolEvidence = [];

        $jp = $signals['judol_posts'] ?? ['count' => 0, 'samples' => []];
        if ($jp['count'] > 0) {
            // Published gambling-titled posts are a strong signal. A couple
            // could be a one-off spam comment turned post; many published ones
            // mean the site is actively compromised — push that to critical.
            //   1 post   → 45 (warning)
            //   ≥5 posts → ≥75 (critical), capped at 90
            $judolScore += min(90, 40 + $jp['count'] * 7);
            $judolEvidence['published_judol_posts'] = $jp['count'];
            // Each sample: {title, url}. url is a clickable ?p=ID link to the
            // live judol page so the operator can verify in one click.
            $judolEvidence['samples'] = $jp['samples'];
        }

        if (! empty($signals['blogname_judol'])) {
            $judolScore += 40;
            $judolEvidence['blogname'] = $signals['blogname'] ?? '';
        }

        if (! empty($signals['redirect_hijack'])) {
            // siteurl/home points off the expected domain — strong hijack sign.
            $judolScore += 50;
            $judolEvidence['offsite_urls'] = $signals['offsite_urls'] ?? [];
        }

        if ($judolScore > 0) {
            $findings[] = $this->finalize(SecscanFinding::THREAT_JUDOL, $judolScore, $judolEvidence);
        }

        // ---- MALWARE (injected content / persistence options) --------------
        $malwareScore = 0;
        $malwareEvidence = [];

        $inj = $signals['injected_content'] ?? ['count' => 0];
        if ($inj['count'] > 0) {
            $malwareScore += min(50, 25 + $inj['count'] * 5);
            $malwareEvidence['injected_posts'] = $inj['count'];
        }

        $sus = $signals['suspicious_options'] ?? 0;
        if ($sus > 0) {
            $malwareScore += min(40, 20 + $sus * 5);
            $malwareEvidence['suspicious_autoload_options'] = $sus;
        }

        if ($malwareScore > 0) {
            $findings[] = $this->finalize(SecscanFinding::THREAT_MALWARE, $malwareScore, $malwareEvidence);
        }

        // ---- SPAM/account anomaly (weak — admin signals) -------------------
        // Admin counts are noisy; treat purely as a low-confidence 'spam'/account
        // signal that never alerts on its own (capped below warning threshold).
        $admin = $signals['admin_stats'] ?? null;
        if ($admin) {
            $accountScore = 0;
            $accountEvidence = [];
            if (($admin['recent_admins'] ?? 0) > 0) {
                $accountScore += 20 * $admin['recent_admins'];
                $accountEvidence['recently_registered_admins'] = $admin['recent_admins'];
            }
            // Only flag "many admins" if it's genuinely high relative to users.
            if (($admin['admins'] ?? 0) >= 5 && $admin['admins'] > ($admin['total_users'] ?? 0)) {
                // admins > total_users is impossible for real data → orphaned
                // meta, NOT a finding. Skip (this was the recon false positive).
            } elseif (($admin['admins'] ?? 0) >= 6) {
                $accountScore += 10;
                $accountEvidence['admin_count'] = $admin['admins'];
                $accountEvidence['total_users'] = $admin['total_users'] ?? null;
            }
            if ($accountScore > 0) {
                $accountEvidence['note'] = 'Sinyal lemah — verifikasi manual sebelum tindakan.';
                $findings[] = $this->finalize(SecscanFinding::THREAT_SPAM, min($accountScore, 35), $accountEvidence);
            }
        }

        return $findings;
    }

    /**
     * @param  array<string,mixed>  $evidence
     * @return array{threat_type:string, score:int, severity:string, evidence:array}
     */
    protected function finalize(string $threatType, int $score, array $evidence): array
    {
        $score = max(0, min(100, $score));

        return [
            'threat_type' => $threatType,
            'score' => $score,
            'severity' => $this->severityFor($score),
            'evidence' => $evidence,
        ];
    }

    protected function severityFor(int $score): string
    {
        $critical = (int) config('nawasara-secscan.thresholds.critical', 70);
        $warning = (int) config('nawasara-secscan.thresholds.warning', 40);

        if ($score >= $critical) {
            return SecscanFinding::SEVERITY_CRITICAL;
        }
        if ($score >= $warning) {
            return SecscanFinding::SEVERITY_WARNING;
        }

        return SecscanFinding::SEVERITY_INFO;
    }
}
