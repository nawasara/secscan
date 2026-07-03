# nawasara/secscan

Security threat detection & response for the Nawasara superapp. Two independent
sources of signal feed one dashboard:

1. **Database scanner** — reads the MySQL databases already monitored by
   `nawasara/database-monitor` (read-only) for indicators of compromise on
   hosted sites (WordPress in particular).
2. **Host agents** (`nawasara-agent`) — a Go binary installed on each server
   that tails logs, watches SSH, and scans the filesystem for webshells /
   backdoors, reporting incidents + findings back to the dashboard.

Everything is **detect + alert** — the database scanner never writes to OPD
databases. Findings get a confidence score (0-100) and severity, a triage
workflow (open / acknowledged / false-positive / resolved), a dashboard, and
alerts via `nawasara/alerting`.

---

## Dashboard pages

| Page | Route | Isi |
|---|---|---|
| Dashboard | `/nawasara-secscan/dashboard` | Ringkasan: agent online, incident kritis, temuan mendesak |
| Temuan Website | `/nawasara-secscan/findings` | Temuan dari database scanner (judol/malware/defacement) + triage |
| Incidents | `/nawasara-secscan/incidents` | Insiden dari agent (SSH brute-force, exploit chain, scanner bot) |
| Agents | `/nawasara-secscan/agents` | Daftar agent terpasang + detail (scan findings, command queue) |
| IP Timeline | `/nawasara-secscan/ip/{ip}` | Semua insiden dari satu IP sumber |

Permissions: `secscan.view`, `secscan.finding.triage`, `secscan.agent.view`,
`secscan.agent.scan`, `secscan.agent.command`.

---

## Setup (database scanner)

1. `nawasara/database-monitor` harus dikonfigurasi (Vault group `database-monitor`)
   — secscan pakai ulang koneksi read-only-nya.
2. Seed permission:
   ```bash
   php artisan db:seed --class="Nawasara\Secscan\Database\Seeders\PermissionSeeder"
   ```
3. Scan berjalan otomatis (scheduler). Trigger manual dari tombol "Pindai sekarang"
   di dashboard, atau:
   ```php
   \Nawasara\Secscan\Jobs\ScanWordpressJob::dispatch(triggerSource: 'manual');
   ```

---

# Panduan Install nawasara-agent

Agen keamanan yang dipasang di **tiap server target**. Memantau log (nginx, SSH,
Laravel), mendeteksi serangan (brute-force, exploit, scanner bot), dan
memindai file berbahaya (webshell/backdoor), lalu melaporkan ke dashboard.

**Butuh:** akses root/sudo · Linux (amd64/arm64) · ± 3 menit

## Cara cepat — satu baris (direkomendasikan)

Jalankan di server target sebagai root:

```bash
curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
```

Skrip ini otomatis:
1. Unduh binary sesuai arsitektur (amd64/arm64)
2. **Daftar ke dashboard** → dapat `agent_id` + `api_key` otomatis
3. Tulis config (`/etc/nawasara-agent/config.yaml`, `chmod 600`)
4. Pasang service systemd (`nawasara-agent run --config …`)
5. Jalankan service

Tidak perlu langkah manual. Output sukses:

```
==> Registering agent with dashboard...
    Registered — agent_id: RmKhmpjHXaAoPXYOL4vx…
==> Installation complete! Agent registered + running.
    config : /etc/nawasara-agent/config.yaml
    logs   : tail -f /var/log/nawasara-agent/agent.log
```

> **Sudah pernah pasang?** Jika `/etc/nawasara-agent/config.yaml` sudah ada,
> skrip melewati pendaftaran (kredensial lama dipertahankan). Untuk daftar ulang
> dari awal, hapus config dulu:
> ```bash
> rm -f /etc/nawasara-agent/config.yaml
> curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
> ```

## Verifikasi

```bash
# 1. Status service — harus "active (running)"
systemctl status nawasara-agent

# 2. Pantau log — cari heartbeat, jangan ada "HTTP 403" berulang
tail -f /var/log/nawasara-agent/agent.log
```

Lalu buka **Dashboard → Security Scan → Agents**. Server muncul **online** dalam
± 30 detik (interval heartbeat).

## Konfigurasi

Config ditulis otomatis ke `/etc/nawasara-agent/config.yaml`. Sentuh hanya untuk
menyesuaikan path log atau menyalakan pemindai file.

| Field | Arti |
|---|---|
| `dashboard_url` | Alamat dashboard Nawasara (terisi otomatis) |
| `agent_id` | ID unik agen (dapat otomatis saat pendaftaran) |
| `api_key` | Kunci auth (`nwa_…`, dapat otomatis, disimpan `chmod 600`) |
| `heartbeat_interval` | Interval heartbeat (default `30s`) |
| `plugins.enabled` | Kolektor aktif: `nginx`, `ssh`, `laravel` |
| `plugins.laravel.log_paths` | Daftar path log Laravel yang dipantau |
| `scanner.enabled` | Pemindai file webshell/backdoor (default `false`) |
| `scanner.scan_interval` | Interval scan (default `6h`) |
| `scanner.web_dirs` | Direktori web yang dipindai saat scanner aktif |
| `scanner.watch_paths` | Path yang dipantau perubahan integritas (mis. `.env`, `/etc/nginx`) |

**Struktur config (contoh):**

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
  enabled: false                 # set true untuk aktifkan pemindai file (Fase 3)
  scan_interval: 6h
  web_dirs:
    - /var/www/html
    - /home/*/public_html
  watch_paths:
    - /etc/nginx
    - /var/www/html/.env
  hash_db: /var/lib/nawasara-agent/hashes.db
```

**Menyalakan pemindai file (Fase 3):** edit config → `scanner.enabled: true` →
sesuaikan `web_dirs` & `watch_paths` → restart:

```bash
nano /etc/nawasara-agent/config.yaml
systemctl restart nawasara-agent
```

## Cara manual (kalau `curl | bash` dilarang kebijakan server)

**1. Unduh binary** (ganti `amd64` → `arm64` untuk server ARM):

```bash
curl -sSL -o /usr/local/bin/nawasara-agent \
  https://nawasara.ponorogo.go.id/agent/download/latest/linux/amd64/nawasara-agent
chmod +x /usr/local/bin/nawasara-agent
```

**2. Daftarkan agen** (catat `agent_id` + `api_key` — api_key hanya muncul sekali):

```bash
curl -s -X POST https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$(hostname)\",\"hostname\":\"$(hostname)\",\"os\":\"linux\",\"arch\":\"$(uname -m)\"}"
```

**3. Tulis config** `/etc/nawasara-agent/config.yaml` — tempel `agent_id`/`api_key`
dari langkah 2, ikuti struktur di atas.

**4. Buat service systemd** `/etc/systemd/system/nawasara-agent.service`.
⚠️ `ExecStart` **wajib** pakai subcommand `run`:

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

**5. Aktifkan & jalankan:**

```bash
systemctl daemon-reload
systemctl enable --now nawasara-agent
```

## Pemecahan masalah

**🔴 Skrip berhenti "Registration failed"** — endpoint pendaftaran tak terjangkau
(firewall / tantangan bot Cloudflare memblokir curl dari VM). Uji manual:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"t","hostname":"t","os":"linux","arch":"x86_64"}'
```

Harus `201`. Kalau `403`/timeout → minta admin membuka jalur `/agent/*` dari IP
server ini di WAF Cloudflare.

**🔴 Log terus "HTTP 403, buffering"** — laporan ditolak; buffer lama menyimpan
payload gagal. Bersihkan buffer lalu restart:

```bash
rm -f /var/lib/nawasara-agent/buffer.db
systemctl restart nawasara-agent
```

Kalau masih 403, sumbernya bukan di agen — hubungi admin dashboard untuk cek
gating `/api/agent/*`.

**🟠 status=203/EXEC saat start** — `ExecStart` tanpa subcommand `run`. Pastikan
barisnya `… nawasara-agent run --config …`, lalu:

```bash
systemctl daemon-reload && systemctl restart nawasara-agent
```

**🟠 Binary hanya beberapa byte / "Not Found"** — unduhan mengembalikan halaman
error. Cek ukuran (harus belasan MB):

```bash
ls -lh /usr/local/bin/nawasara-agent
```

Kalau kecil → repo release belum publik atau tag rilis salah. Unduh ulang setelah
admin mengonfirmasi release tersedia.

## Checklist akhir

- [ ] Binary di `/usr/local/bin/nawasara-agent` (belasan MB)
- [ ] `agent_id` & `api_key` tidak kosong di `/etc/nawasara-agent/config.yaml`
- [ ] `systemctl status nawasara-agent` → `active (running)`
- [ ] Log ada heartbeat, tidak ada `403` berulang
- [ ] Server tampil **online** di Security Scan → Agents

---

## Agent binary release

Binary di-build via GitHub Actions (`release.yml`) saat push tag ke repo
`nawasara/agent` (linux/amd64 + linux/arm64). Dashboard menyajikan:

- `GET /agent/install.sh` — installer one-liner (text/plain)
- `GET /agent/download/latest/linux/{arch}/nawasara-agent` — redirect ke GitHub
  release asset terbaru

> Repo release harus **public** agar download asset tak 404.

## Roadmap

- **F1:** SQL signal detector + findings + triage UI + alerts. ✅
- **F2:** Host agent — log collectors (nginx/ssh/laravel) + incident reporting. ✅
- **F3:** Agent file scanner — webshell/backdoor signatures + file integrity. ✅
- **F4:** Live HTTP probe (cloaking, redirect-on-fetch) via sidecar.
- **F5:** Auto-response — block malicious source IP via `nawasara/opnsense`
  firewall blocklist (`FirewallBlocklistService::block($ip)`).
