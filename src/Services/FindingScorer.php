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
        $strongCount = (int) ($signals['judol_strong_count'] ?? 0);
        if ($jp['count'] > 0) {
            // Published gambling-titled posts (whole-word matched, so "dewan" /
            // anti-gambling articles no longer false-positive). Strong keywords
            // (casino/gacor/scatter/…) never appear in gov content, so even a
            // single strong-keyword post is high-confidence — start at 70
            // (critical). Weak-only matches that got here were already
            // corroborated (foreign script / a strong hit on the same site).
            if ($strongCount > 0) {
                $judolScore += min(90, 65 + $strongCount * 4);
            } else {
                $judolScore += min(70, 45 + $jp['count'] * 5);
            }
            $judolEvidence['published_judol_posts'] = $jp['count'];
            if ($strongCount > 0) {
                $judolEvidence['strong_keyword_posts'] = $strongCount;
            }
            // Each sample: {title, url}. url is a clickable ?p=ID link to the
            // live judol page so the operator can verify in one click.
            $judolEvidence['samples'] = $jp['samples'];

            // Foreign-script booster: titles in Turkish/Greek/Cyrillic etc. are
            // near-certain spam injection on a *.go.id site → confident critical.
            if (! empty($signals['judol_foreign'])) {
                $judolScore = max($judolScore, 90);
                $judolEvidence['foreign_script'] = true;
            }
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

        // ---- ILLEGAL PHARMA (abortion-drug SEO spam) -----------------------
        // Mirror of the judol block. Strong terms ("penggugur kandungan", "jual
        // obat aborsi") never appear in legit puskesmas content → high confidence
        // on a single hit. Weak clinical terms reaching here were already
        // corroborated by a strong hit on the same site (SqlSignalDetector).
        $pharmaScore = 0;
        $pharmaEvidence = [];

        $pp = $signals['pharma_posts'] ?? ['count' => 0, 'samples' => []];
        $pStrongCount = (int) ($signals['pharma_strong_count'] ?? 0);
        if ($pp['count'] > 0) {
            if ($pStrongCount > 0) {
                $pharmaScore += min(90, 65 + $pStrongCount * 4);
                $pharmaEvidence['strong_keyword_posts'] = $pStrongCount;
            } else {
                $pharmaScore += min(70, 45 + $pp['count'] * 5);
            }
            $pharmaEvidence['published_pharma_posts'] = $pp['count'];
            $pharmaEvidence['samples'] = $pp['samples'];
        }

        if ($pharmaScore > 0) {
            $findings[] = $this->finalize(SecscanFinding::THREAT_ILLEGAL_PHARMA, $pharmaScore, $pharmaEvidence);
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

        // ---- BACKDOOR (admin-account anomaly) ------------------------------
        // A burst of newly-created admin accounts is one of the strongest signs
        // of a real compromise: an attacker mass-creates admins (often with
        // gmail addresses, in one sitting) for persistence. Legit gov sites add
        // admins one at a time over months. This used to be a weak 'spam' info
        // signal; real prod data (ponorogokab: 5 gmail admins created in ~2 days
        // — adminbackup@gmail.com etc.) showed it deserves to be loud.
        $admin = $signals['admin_stats'] ?? null;
        if ($admin) {
            $score = 0;
            $evidence = [];

            $recent = (int) ($admin['recent_admins'] ?? 0);
            $recentNonGov = (int) ($admin['recent_nongov_admins'] ?? 0);
            $burst = ! empty($admin['registration_burst']);

            if ($recent > 0) {
                // Each newly-registered admin in the last 30 days adds weight;
                // non-gov emails weigh more.
                $score += $recent * 12 + $recentNonGov * 10;
                $evidence['recently_registered_admins'] = $recent;
                if ($recentNonGov > 0) {
                    $evidence['non_gov_email_admins'] = $recentNonGov;
                }
                if (! empty($admin['recent_admin_list'])) {
                    $evidence['accounts'] = $admin['recent_admin_list'];
                }
            }

            if ($burst) {
                // Several admins created in a tight window → backdoor pattern.
                $score = max($score, 80);
                $evidence['registration_burst'] = true;
            }

            if ($score >= (int) config('nawasara-secscan.thresholds.warning', 40)) {
                // Only surface as an actionable finding when it crosses warning.
                // Below that it's just normal admin churn — don't bother ops.
                $findings[] = $this->finalize(SecscanFinding::THREAT_BACKDOOR, $score, $evidence);
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
