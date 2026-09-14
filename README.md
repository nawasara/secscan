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

Permissions: `secscan.view`, `secscan.finding.triage`, `secscan.agent.view`,
`secscan.agent.scan`, `secscan.agent.command`.

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

Run this on the target server as root:

```bash
curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
```

The script automatically:
1. Downloads the binary for the architecture (amd64/arm64)
2. **Registers with the dashboard**, receiving `agent_id` plus `api_key` automatically
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
> curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
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

**Script stops at "Registration failed".** The registration endpoint is
unreachable (a firewall or Cloudflare bot challenge is blocking curl from the
VM). Test manually:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
  https://nawasara.ponorogo.go.id/api/agent/register \
  -H 'Content-Type: application/json' \
  -d '{"name":"t","hostname":"t","os":"linux","arch":"x86_64"}'
```

It should be `201`. If it is `403` or times out, ask an admin to open the
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
- **F4:** Live HTTP probe (cloaking, redirect-on-fetch) via sidecar.
- **F5:** Auto-response, blocking a malicious source IP via the `nawasara/opnsense`
  firewall blocklist (`FirewallBlocklistService::block($ip)`).
