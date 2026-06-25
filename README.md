# nawasara/secscan

Security threat detection for the Nawasara superapp. Scans the MySQL databases
already monitored by `nawasara/database-monitor` (read-only) — WordPress sites
in particular — for indicators of compromise:

- **Judol / gambling SEO spam** — published posts/blognames with gambling keywords
- **Defacement / redirect hijack** — `siteurl`/`home` pointing off the gov domain
- **Malware** — injected `<script display:none>` / `eval(base64)` content, suspicious autoload options
- **Account anomalies** — recently-registered admins (weak signal, verify manually)

It is **detect + alert only** — it never writes to the OPD databases. Findings
get a confidence score (0-100) and severity, are stored with a triage workflow
(open / acknowledged / false-positive / resolved), shown on a dashboard, and
raised as alerts via `nawasara/alerting`.

## Setup

1. `nawasara/database-monitor` must be configured (Vault group `database-monitor`)
   — secscan reuses its read-only connection.
2. Seed permissions:
   ```bash
   php artisan db:seed --class="Nawasara\Secscan\Database\Seeders\PermissionSeeder"
   ```
3. The hourly scan runs automatically (scheduler). Trigger manually from the
   Dashboard "Pindai sekarang" button, or:
   ```php
   \Nawasara\Secscan\Jobs\ScanWordpressJob::dispatch(triggerSource: 'manual');
   ```

## Roadmap

- **F1 (this):** SQL signal detector + findings + triage UI + alerts.
- **F2:** Python sidecar for live HTTP probe (cloaking, redirect-on-fetch).
- **F3:** Google Custom Search index check (`site:domain slot|judi`).
