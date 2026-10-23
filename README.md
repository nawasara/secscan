# nawasara/secscan

Security threat detection and response for the Nawasara superapp. Two
independent sources of signal feed one dashboard:

1. **Database scanner.** Reads the MySQL databases already monitored by
   `nawasara/database-monitor` (read-only) for indicators of compromise on
   hosted sites (WordPress in particular).
2. **Host agents** (`nawasara-agent`). A Go binary installed on each server that
   tails logs, watches SSH, and scans the filesystem for webshells and
   backdoors, reporting incidents and findings back to the dashboard.

Everything is **detect plus alert**: the database scanner never writes to OPD
databases. Findings get a confidence score (0-100) and severity, a triage
workflow (open / acknowledged / false-positive / resolved), a dashboard, and
alerts via `nawasara/alerting`.

---

## Dashboard pages

| Page | Route | Contents |
|---|---|---|
| Dashboard | `/nawasara-secscan/dashboard` | Summary: agents online, critical incidents, urgent findings |
| Temuan Website | `/nawasara-secscan/findings` | Findings from the database scanner (gambling spam/malware/defacement) plus triage |
| Incidents | `/nawasara-secscan/incidents` | Incidents from the agent (SSH brute-force, exploit chain, scanner bot) |
| Agents | `/nawasara-secscan/agents` | List of installed agents plus detail (scan findings, command queue) |
| IP Timeline | `/nawasara-secscan/ip/{ip}` | Every incident from one source IP |
| Versi PHP | `/nawasara-secscan/php-runtimes` | Versi PHP seluruh situs dan server: dari luar, dari server WHM, dan dari agen |

Permissions: `secscan.view`, `secscan.finding.triage`, `secscan.agent.view`,
`secscan.agent.scan`, `secscan.agent.command`.

### IP blocks never expire, so the page is the cleanup path

Decided on 8 October 2026: blocks stay until someone lifts them (566 active
at the time, 455 older than 30 days). Blokir IP therefore filters by reason,
source and age, and "Cabut N blokir" lifts the whole filtered result. It only
appears once the list is narrowed, is sudo-gated, and runs as queued jobs of
100 (one Cloudflare call each; a worker kills a job at the smaller of its own
and the worker's timeout).

Every manual block and every unblock goes through `Services\IpBlockManager`,
for the panel and the API alike. An unblock that Cloudflare refuses changes
nothing. The panel used to mark such a block "removed" anyway, so it showed
an IP as unblocked while Cloudflare kept dropping it.

### Retiring an agent

"Cabut agen" (permission `secscan.agent.delete`, sudo) soft-deletes the agent,
replaces its key hash, cancels its pending and approved commands, and
resolves its offline alert. The commands matter: a dead agent never pulls
them, and 170 had piled up as approved, which the panel read as "blocked on
the host". Incidents keep naming a revoked agent (`withTrashed`).

Online/offline is one rule everywhere (`Agent::online()` / `offline()`, last
heartbeat within 180 s), and "hari ini" counts from midnight WIB
(`SecurityIncident::today()`); the app timezone is UTC.

### Finding status follows the scanner

Every status change, by staff or by a scanner, goes through
`Services\FindingTriage`, so each one leaves a history row.

- **Selesai detected again by the HTTP probe is reopened** to Terbuka and
  alerts again: the live page is still serving it. It used to stay Selesai
  while `last_detected_at` kept moving, so nobody was told.
- **Selesai detected again by the database scan is NOT reopened**, only
  marked "Masih ada di database" (`SecscanFinding::stillInDatabase()`).
  The usual fix is suspending the cPanel account, which takes the site
  offline but leaves the injected rows; in production 16 of 19 such findings
  were exactly that, and reopening them would alert about offline sites. The
  mark keeps the dirty database from being forgotten when the account comes
  back.
- **False positive is never reopened.** That is staff saying the detector is
  wrong about the site; the detector repeating itself does not change that.
  Use Selesai for "cleaned", False positive for "the detector is wrong".
- **Active findings close themselves** once the site was scanned cleanly and
  the signal has been absent for `auto_resolve_after_hours` (24). Only
  databases whose sweep finished, and pages actually fetched, count: a scan
  that errored or was time-boxed says nothing about whether a site is clean.
  24 h rather than one scan, so a score hovering at the threshold does not
  close and reopen every hour.
- The page opens on **Terbuka + Diakui**. Diakui means someone is on it, not
  done, so it stays visible.

### Deteksi konten situs: tiga lapis, dan apa yang tidak dilihat masing-masing

Halaman judol "SLOT777 LOGIN" di `umum.ponorogo.go.id` (16 Oktober 2026)
sampai ke hasil Google tanpa satu pun peringatan. Penelusurannya menemukan
bahwa ketiga lapis buta terhadapnya, masing-masing karena alasan berbeda:

| Lapis | Yang dibaca | Buta terhadap |
|---|---|---|
| Scan database (tiap jam) | Kolom konten DB di server DB yang dipantau | Berkas statis, route, DB di server lain |
| Probe HTTP (tiap 6 jam) | `/` + path WP + beberapa URL sitemap | URL dalam yang tidak tertaut dan tidak ada di sitemap |
| Agen, pemindai berkas (tiap 6 jam) | Berkas di `web_dirs` server ber-agen | **Server tanpa agen** — umum ada di Himalaya (.29), agennya hanya di alpine (.30) |

Jadi menaikkan frekuensi cron **tidak** menolong; yang menentukan adalah apa
yang dibaca. Keputusan yang sebaiknya tidak dibatalkan:

- **Temuan berkas agen memicu alert, satu per situs** (`FileFindingAlerts`).
  Sebelumnya `scanFinding` hanya menyimpan baris: 124 halaman judol di akun
  Jambon terbuka sejak 14 Juli tanpa pemberitahuan. Satu alert per berkas
  akan mengirim 124 pesan untuk satu kejadian. Kuncinya `agen:akar-situs`
  supaya stabil antar-pemindaian; alert pulih otomatis saat berkas terakhir
  situs itu ditangani, atau tidak dilaporkan lagi selama `file_stale_hours`
  (30) oleh agen yang masih hidup. **Akun cPanel yang di-suspend tidak
  di-alert** (dibaca dari `nawasara_whm_accounts`): Jambon di-suspend karena
  "Indikasi judol" sementara 124 berkasnya masih di disk — situsnya sudah
  mati, pengingat harian hanya kebisingan. Barisnya tetap terbuka supaya
  pembersihan berkas tidak terlupa.
- **Integritas berkas cache/log tidak dicatat** (`Support\VolatilePath`,
  cerminan `internal/scanner/volatile.go` di agen — jaga keduanya sama).
  Pemindaian *signature* tetap berjalan di path itu: judol yang ditaruh di
  folder cache tetap tertangkap. Tetapi cache/log **bukan** sumber utama
  kebisingan: dari 29.263 temuan integritas terbuka di alpine (diukur 16 Okt
  2026) hanya 1.818 yang cache/log. **27.445 adalah berkas inti WordPress dan
  plugin** (`wp-includes/js` 8.001, `wp-content/plugins` 6.562) yang berubah
  bergelombang — 9.176 dalam satu hari pada 20 Agustus — yakni pembaruan WP.
  Path itu sengaja TIDAK dilewati: di sanalah backdoor biasa disisipkan.
  Penyelesaiannya adalah mencocokkan dengan checksum resmi WordPress
  (`api.wordpress.org/core/checksums`) — lihat Roadmap.
- **Beranda dibaca dua kali**: sebagai Googlebot dan sebagai ponsel yang
  datang dari Google (`Referer: google.com`). Cloaking judol menampilkan
  halaman bersih kepada yang mengetik URL dan menukarnya hanya untuk lalu
  lintas pencarian. Sinyal yang hanya terlihat oleh satu jenis pengunjung
  diberi evidence `cloaking`. Pembanding *ukuran badan respons* (dulu
  `fetchBoth()`, tidak pernah dipanggil) sengaja tidak dipakai — beranda
  dinamis berubah ukuran tanpa cloaking apa pun.
- **Slug sitemap diperiksa sebelum halamannya diambil.** Sitemap situs
  pemerintah yang memuat `/slot-gacor-maxwin/` sudah merupakan bukti. "slot"
  tanpa angka tidak dihitung: `slot-anggaran` adalah berita sungguhan.
- **Path WordPress hanya untuk situs WordPress.** Memeriksa `/wp-login.php`
  di situs Laravel hanya menghabiskan kuota harian host.
- Alert konten (`secscan.site.*`, `secscan.file.spam`) masuk topik Telegram
  **Spam & Konten Ilegal** (`topic_konten` di Vault), bukan Kritis: yang
  membersihkannya pengelola situs OPD, bukan admin jaringan. Webshell
  (`secscan.file.malicious`) tetap di Kritis.

### "Lihat kode" pada temuan berkas agen

Agen ≥ v0.13.0 mengirim ±15 baris di sekitar temuan (maks 300 byte per baris,
4 KB total) beserta nomor barisnya; dasbor menampilkannya di menu ⋯ →
**Lihat kode**. Sebagian besar temuan (plugin yang menulis `index.php`-nya
sendiri, JS termampatkan) dapat diputuskan *false positive* dalam hitungan
detik tanpa SSH.

Dua keputusan yang jangan dibatalkan:

- **Konteks diambil saat deteksi, bukan dibaca sesuai permintaan.** Tombol
  "buka berkas" yang menyuruh agen membaca berkas apa pun akan menjadikan agen
  pembaca berkas jarak jauh: siapa pun yang membobol dasbor dapat menarik
  setiap `wp-config.php` di setiap server.
- **Kredensial disamarkan DI AGEN**, sebelum keluar dari host (`define()`
  kunci/sandi, baris `.env`, array `password =>`, `$db_pass = ...`). Dasbor
  tidak pernah menerima nilainya, jadi tidak ada yang perlu disaring di sini.

Temuan dari agen lama hanya punya potongan 120 karakter; modal menampilkannya
dengan catatan untuk memperbarui agen.

Yang **masih** belum tertangkap: cloaking berbasis IP Googlebot asli (reverse
DNS) dan konten yang disisipkan JavaScript sesudah halaman dimuat — yang
kedua butuh browser headless (lihat Roadmap F4).

### Versi PHP: tiga arah, karena tidak ada satu pun yang melihat semuanya

Lahir dari PHP2Shell (CVE-2026-109618/109619, Oktober 2026). Survei manual
pertama menemukan e-bmd dan simap di PHP 5.6, smep di 7.4, enam situs
Himalaya di 8.1 (tak akan pernah ditambal), dan penataanruang di 8.2.30
(tambalan ada, belum dipasang). Halaman ini mengulang survei itu tiap pagi
pukul 05.15 WIB (`ScanPhpRuntimesJob`).

| Arah | Melihat | Buta terhadap |
|---|---|---|
| Dari luar | Semua hostname A/AAAA/CNAME di DNS Cloudflare | Versi, kecuali situs memasang `X-Powered-By` |
| Server WHM | Handler PHP tiap vhost cPanel | Server tanpa kunci SSH di Vault |
| Agen (v0.15.0+) | Host, ea-php, alt-php, container Docker | Host tanpa agen |

Keputusan yang tampak keliru tetapi disengaja:

- **WHM dibaca lewat SSH, bukan API.** Token API WHM di Vault ditolak untuk
  `php_get_vhost_versions` ("Permission denied", diuji 23 Oktober 2026).
  Instance tanpa `ssh_key` dilewati dan dicatat di log, bukan dianggap kosong.
- **Satu peringatan per golongan, bukan per situs.** `secscan.php.vulnerable`
  (critical) dan `secscan.php.eol` (warning), target tetap `summary`, jeda 1
  hari. Per situs berarti belasan pesan Telegram tiap pagi untuk masalah yang
  sama. Keduanya selesai sendiri saat jumlahnya nol.
- **8.1 tetap "tidak didukung" meski cPanel mungkin menambalnya sendiri.**
  Tambalan vendor yang tak terlihat dari nomor versi bukan rencana.
- **Pindaian luar mengikuti satu redirect.** Tanpa itu survei pertama hanya
  melihat 12 dari 274 hostname: banyak aplikasi langsung mengalihkan ke
  `/login`, dan cookie sesinya baru muncul di sana.
- **Hostname yang mengarah ke alamat dalam dilewati** (`OutboundUrlGuard`).

Saat ada CVE PHP baru, perbarui `SECSCAN_PHP_PATCHED` (versi aman pertama per
cabang, dipisah koma) dan `SECSCAN_PHP_ADVISORY`, lalu tekan **Pindai
Sekarang**. Status dihitung ulang dari versinya, tanpa migrasi.

---

## Setup (database scanner)

1. `nawasara/database-monitor` must be configured (Vault group
   `database-monitor`); secscan reuses its read-only connection.
2. Seed permissions:
   ```bash
   php artisan db:seed --class="Nawasara\Secscan\Database\Seeders\PermissionSeeder"
   ```
3. The scan runs automatically (scheduler). Trigger it manually from the "Pindai
   sekarang" button on the dashboard, or:
   ```php
   \Nawasara\Secscan\Jobs\ScanWordpressJob::dispatch(triggerSource: 'manual');
   ```

---

## API

Requires [`nawasara/api`](../nawasara-api). If that package is not installed, the routes are not mounted and nothing changes.

Authentication: `Authorization: Bearer nws_…` or `X-API-Key: nws_…`. Every path is prefixed with `/api/v1/secscan`.

Do not confuse this with `/api/agent/*`, which is the path agents use to report to the server; it authenticates with `X-Agent-Key` and has nothing to do with the tokens or scopes below.

### Scope

| Scope | Access |
|---|---|
| `secscan.incident.read` | Incidents from the agent |
| `secscan.finding.read` | Website findings |
| `secscan.agent.read` | Agent status |
| `secscan.stats.read` | Aggregate statistics |
| `secscan.ipblock.read` | List of blocked IPs |
| `secscan.ipblock.write` | Block a new IP |
| `secscan.ipblock.delete` | Unblock |

Split per domain so a token can be given narrow access: a consumer that only needs statistics does not also need to read every incident and its attacker IP. Configure this in **Pengaturan → API Token**.

### Endpoints

| Method | Path | Query params |
|---|---|---|
| GET | `/incidents` | `severity`, `type`, `ip`, `blocked`, `since`, `per_page` |
| GET | `/incidents/{incidentId}` | |
| GET | `/findings` | `status` (default active; `all` for everything), `threat`, `severity`, `q`, `per_page` |
| GET | `/findings/{id}` | |
| GET | `/agents` | `status`, `per_page` |
| GET | `/agents/{agentId}` | |
| GET | `/stats` | `days` (1-90, default 1) or `from`+`to` (ISO8601) |
| GET/POST/DELETE | `/ip-blocks` | see the IP block section |

Multi-value parameters accept commas: `?severity=high,critical`.

```bash
curl -H "Authorization: Bearer nws_xxx" \
  "https://nawasara.ponorogo.go.id/api/v1/secscan/stats?days=7"
```

```json
{
  "data": {
    "total": 1,
    "by_severity": { "critical": 1 },
    "by_type": { "sqli_attempt": 1 },
    "top_ips": [{ "ip": "203.0.113.99", "count": 1, "score": 95 }],
    "top_hosts": [{ "host": "dinaskesehatan.ponorogo.go.id", "count": 1 }],
    "blocked": 0, "blocked_active": 0,
    "agents_online": 1, "agents_total": 1
  },
  "meta": { "from": "…", "to": "…" }
}
```

These numbers come from the same `IncidentStatsCollector` as the daily email digest, so the two cannot silently diverge.

### What is never returned

Each Resource is an allow-list, not a filtered dump. Deliberately withheld:

- **Incident `evidence`**: raw log lines. A single full request line can contain a query string with a token or session id, an attempted SSH username, and the attack payload verbatim. Only its `host` field is taken, and it appears as `targets`.
- **Incident `metadata`**: a free-form blob from the agent, validated only as `nullable|array`. Its contents are not controlled.
- **Finding `evidence`**: contains `accounts.recent_admin_list` and `non_gov_email_admins`, a list of WordPress admin accounts with their emails. That is PII, and also a neat list of phishing targets.
- **`db_name`**: the database schema name on a shared server.
- **Agent detail**: `api_key_hash` (a credential), `ip_local` (a private IP), `hostname`, `agent_version`, `os`, `web_server`, `plugins_active`. Each one looks trivial on its own; together they read as "server X runs nginx on Ubuntu 20.04", a shopping list for an attacker looking for vulnerable versions.
- **`AgentCommand` in full**: this is the control plane. Exposing it, even read-only, reveals what remote commands can be run on an OPD server.
- **`cf_rule_id` and `notes` on IP blocks**: the Cloudflare handle and the audit trail.

Widening this list is a deliberate decision, not a convenience: change the Resource, and write down why in the same commit.

### Restrict tokens by IP

`top_hosts` is a list of our own sites that are attacked most often. Useful for prioritizing defense, but if the token leaks it is a ready-made target list. The same goes for `source_ip` on incidents.

Put an **IP allow-list** on every token that carries a secscan scope, through the API Token page.

---

# nawasara-agent install guide

The security agent installed on **every target server**. It monitors logs
(nginx, SSH, Laravel), detects attacks (brute-force, exploit, scanner bot), and
scans for malicious files (webshell/backdoor), then reports to the dashboard.

**Needs:** root/sudo access, Linux (amd64/arm64), about 3 minutes.

## Quick way: one line (recommended)

> **Enrollment token required (since the 15 October 2026 security audit, T1).**
> `/api/agent/register` used to be open to anyone, and a self-registered agent
> could make the Decision Engine block any IP on Cloudflare. Now an admin with
> `secscan.agent.enroll` creates a one-time token on the Agents page
> (**Buat Token**, needs sudo; valid 1 hour to 7 days). The new agent then sits
> in **Menunggu persetujuan** until an admin approves it from the row menu:
> its incidents are stored but never trigger a block, and it receives no
> commands.

Run this on the target server, with the token from the Agents page:

```bash
curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | sudo NAWASARA_ENROLLMENT_TOKEN=nwe_xxx bash
```

The script automatically:
1. Downloads the binary for the architecture (amd64/arm64)
2. **Registers with the dashboard** using the enrollment token, receiving `agent_id` plus `api_key`
3. Writes the config (`/etc/nawasara-agent/config.yaml`, `chmod 600`)
4. Installs the systemd service (`nawasara-agent run --config …`)
5. Starts the service

No manual step is needed. Successful output:

```
==> Registering agent with dashboard...
    Registered - agent_id: RmKhmpjHXaAoPXYOL4vx…
==> Installation complete! Agent registered + running.
    config : /etc/nawasara-agent/config.yaml
    logs   : tail -f /var/log/nawasara-agent/agent.log
```

> **Installed before?** If `/etc/nawasara-agent/config.yaml` already exists, the
> script skips registration (the old credentials are kept). To register again
> from scratch, remove the config first:
> ```bash
> rm -f /etc/nawasara-agent/config.yaml
> curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | sudo NAWASARA_ENROLLMENT_TOKEN=nwe_xxx bash
> ```

## Verification

```bash
# 1. Service status: should be "active (running)"
systemctl status nawasara-agent

# 2. Watch the log: look for heartbeats, no repeated "HTTP 403"
tail -f /var/log/nawasara-agent/agent.log
```

Then open **Dashboard → Security Scan → Agents**. The server appears **online**
within about 30 seconds (the heartbeat interval).

## Configuration

The config is written automatically to `/etc/nawasara-agent/config.yaml`. Touch
it only to adjust log paths or turn on the file scanner.

| Field | Meaning |
|---|---|
| `dashboard_url` | The Nawasara dashboard address (filled in automatically) |
| `agent_id` | The agent's unique ID (received automatically at registration) |
| `api_key` | Auth key (`nwa_…`, received automatically, stored `chmod 600`) |
| `heartbeat_interval` | Heartbeat interval (default `30s`) |
| `plugins.enabled` | Active collectors: `nginx`, `ssh`, `laravel` |
| `plugins.laravel.log_paths` | List of Laravel log paths to watch |
| `scanner.enabled` | Webshell/backdoor file scanner (default `false`) |
| `scanner.scan_interval` | Scan interval (default `6h`) |
| `scanner.web_dirs` | Web directories scanned when the scanner is active |
| `scanner.watch_paths` | Paths watched for integrity changes (e.g. `.env`, `/etc/nginx`) |
| `scanner.integrity_ignore` | Extra path substrings skipped by the integrity check (agent ≥ v0.12; caches/logs are built in) |

**Config structure (example):**

```yaml
dashboard_url: https://nawasara.ponorogo.go.id
agent_id: <auto>
api_key: <auto>

heartbeat_interval: 30s

plugins:
  enabled:
    - nginx
    - ssh
    - laravel
  laravel:
    log_paths:
      - /var/www/html/storage/logs/*.log
      - /home/*/public_html/storage/logs/*.log

scanner:
  enabled: false                 # set true to enable the file scanner (Phase 3)
  scan_interval: 6h
  web_dirs:
    - /var/www/html
    - /home/*/public_html
  watch_paths:
    - /etc/nginx
    - /var/www/html/.env
  hash_db: /var/lib/nawasara-agent/hashes.db
```

**Turning on the file scanner (Phase 3):** edit the config, set
`scanner.enabled: true`, adjust `web_dirs` and `watch_paths`, then restart:

```bash
nano /etc/nawasara-agent/config.yaml
systemctl restart nawasara-agent
```

## Manual way (if server policy forbids `curl | bash`)

**1. Download the binary** (change `amd64` to `arm64` for ARM servers):

```bash
curl -sSL -o /usr/local/bin/nawasara-agent \
  https://nawasara.ponorogo.go.id/agent/download/latest/linux/amd64/nawasara-agent
chmod +x /usr/local/bin/nawasara-agent
```

**2. Register the agent** (note the `agent_id` and `api_key`; the api_key only appears once):

```bash
curl -s -X POST https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -H 'X-Enrollment-Token: nwe_xxx' \
  -d "{\"name\":\"$(hostname)\",\"hostname\":\"$(hostname)\",\"os\":\"linux\",\"arch\":\"$(uname -m)\"}"
```

**3. Write the config** `/etc/nawasara-agent/config.yaml`. Paste the
`agent_id`/`api_key` from step 2, following the structure above.

**4. Create the systemd service** `/etc/systemd/system/nawasara-agent.service`.
The `ExecStart` line **must** use the `run` subcommand:

```ini
[Unit]
Description=Nawasara Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nawasara-agent run --config /etc/nawasara-agent/config.yaml
Restart=always
RestartSec=10
User=root
StandardOutput=append:/var/log/nawasara-agent/agent.log
StandardError=append:/var/log/nawasara-agent/agent.log

[Install]
WantedBy=multi-user.target
```

**5. Enable and start:**

```bash
systemctl daemon-reload
systemctl enable --now nawasara-agent
```

## Troubleshooting

**Script stops at "Registration failed" with `401`.** The enrollment token is
missing, expired, revoked, or already used (each token registers exactly one
agent). Create a new one on the Agents page.

**Script stops at "Registration failed" otherwise.** The registration endpoint is
unreachable (a firewall or Cloudflare bot challenge is blocking curl from the
VM). Test manually:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"t","hostname":"t","os":"linux","arch":"x86_64"}'
```

Without a token it should be `401` (reachable). Do not test with a real token:
it would be consumed. If it is `403` or times out, ask an admin to open the
`/agent/*` path from this server's IP in the Cloudflare WAF.

**Log keeps saying "HTTP 403, buffering".** Reports are being rejected, and the
old buffer holds the failed payloads. Clear the buffer, then restart:

```bash
rm -f /var/lib/nawasara-agent/buffer.db
systemctl restart nawasara-agent
```

If it is still 403, the source is not the agent; contact the dashboard admin to
check the `/api/agent/*` gating.

**status=203/EXEC at start.** The `ExecStart` is missing the `run` subcommand.
Make sure the line reads `… nawasara-agent run --config …`, then:

```bash
systemctl daemon-reload && systemctl restart nawasara-agent
```

**Binary is only a few bytes / "Not Found".** The download returned an error
page. Check the size (it should be tens of MB):

```bash
ls -lh /usr/local/bin/nawasara-agent
```

If it is small, the release repo is not public yet or the release tag is wrong.
Download again after an admin confirms the release is available.

## Final checklist

- [ ] Binary at `/usr/local/bin/nawasara-agent` (tens of MB)
- [ ] `agent_id` and `api_key` not empty in `/etc/nawasara-agent/config.yaml`
- [ ] `systemctl status nawasara-agent` shows `active (running)`
- [ ] Log has heartbeats, no repeated `403`
- [ ] Server shows **online** in Security Scan → Agents
- [ ] Agent **approved** (no "Menunggu persetujuan" badge), otherwise its incidents never trigger a block

---

## Agent binary release

The binary is built via GitHub Actions (`release.yml`) when a tag is pushed to
the `nawasara/agent` repo (linux/amd64 plus linux/arm64). The dashboard serves:

- `GET /agent/install.sh`: the one-liner installer (text/plain)
- `GET /agent/download/latest/linux/{arch}/nawasara-agent`: a redirect to the
  latest GitHub release asset

> The release repo must be **public** or the asset download 404s.

## Roadmap

- **F1:** SQL signal detector plus findings plus triage UI plus alerts. Done.
- **F2:** Host agent, with log collectors (nginx/ssh/laravel) plus incident reporting. Done.
- **F3:** Agent file scanner, with webshell/backdoor signatures plus file integrity. Done.
- **F4:** Cloaking. Tahap 1 selesai (v0.17): beranda dibaca sebagai Googlebot
  dan sebagai ponsel dari Google, plus URL sitemap — PHP biasa, tanpa sidecar.
  Tahap 2, browser headless untuk konten yang disisipkan JavaScript, baru
  dibuat bila ada kasus nyata yang lolos dari tahap 1; Chromium butuh
  0,5–1 GB RAM untuk dirawat.
- **Integritas WordPress dengan checksum resmi:** berkas `wp-includes` /
  `wp-admin` yang cocok dengan checksum versi terpasang (dan plugin dari
  `downloads.wordpress.org`) adalah pembaruan, bukan intrusi. Tanpa ini ~27 ribu
  temuan integritas di alpine tidak dapat dibedakan dari backdoor.
- **Search Console:** satu domain property `ponorogo.go.id` mencakup semua
  subdomain; kueri harian kata kunci judol menunjuk URL yang sudah terindeks.
  Gratis, data terlambat 2–3 hari. Kunci service account diblokir kebijakan
  org GCP, jadi butuh OAuth refresh token.
- **F5:** Auto-response, blocking a malicious source IP via the `nawasara/opnsense`
  firewall blocklist (`FirewallBlocklistService::block($ip)`).
