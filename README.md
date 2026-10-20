# NetCheck – Automated Network Health Check

Python tool: SSH (Netmiko) → `ping` / `traceroute` / `show ip route` / interface status → analysis → HTML (+PDF) report → e-mail (SMTP).
Runs in parallel across devices, one broken device never aborts the run.

```
main.py                    CLI entry point (exit code 0 ok | 1 warning | 2 critical | 3 e-mail failed)
config/config.yaml         GNS3 lab config (devices, thresholds, SMTP)   ← real run
config/config.demo.yaml    4 simulated devices                            ← offline demo
netcheck/connector.py      NetmikoConnector (SSH) + DemoConnector (canned output)
netcheck/collector.py      per-device command execution, thread pool, error isolation
netcheck/parsers.py        raw CLI text → objects (pure functions)
netcheck/analyzer.py       thresholds → findings (OK / WARNING / CRITICAL)
netcheck/report.py         Jinja2 HTML + xhtml2pdf PDF
netcheck/templates/        report.html.j2
netcheck/mailer.py         SMTP (plain / STARTTLS / SSL) with attachments
gns3/configs/              R1_addon.cfg, R2.cfg (c3745 lab)
tests/                     18 unit/integration tests
```

## 1. Quick start (no GNS3 needed)

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   |  source .venv/bin/activate  (Linux/macOS)
pip install -r requirements.txt
python main.py -c config/config.demo.yaml --demo --no-email
```
Open `reports/netcheck_*.html`. In VS Code press **F5** and pick a profile from `.vscode/launch.json`.
Tests: `python -m unittest -v` (or `pytest`).

## 2. GNS3 lab (2x Cisco c3745, Telnet, VMware vmnet8)

```
 Cloud (same NIC you used in lab1, VMware vmnet8 192.168.195.0/24)
   │
 Ethernet switch (GNS3 built-in, unmanaged)
   ├── Fa0/0  R1 (c3745) .50 ── Fa1/0 ══ 10.0.12.0/30 (OSPF area 0) ══ Fa1/0 ── R2 (c3745) .51 ── Fa0/0 ─┐
   └────────────────────────────────────────────────────────────────────────────────────────────────────┘
 R1: Loopback10 10.10.10.1, Loopback20 10.20.20.1      R2: Loopback10 10.30.30.1      NAT gateway: 192.168.195.2
```

1. Keep your lab1 router as **R1**; add a second **c3745** as **R2**; connect both `Fa0/0` to the GNS3 *Ethernet switch*, and the switch to the Cloud.
   Cable `R1 Fa1/0` ↔ `R2 Fa1/0`.
2. Paste `gns3/configs/R1_addon.cfg` into R1 and `gns3/configs/R2.cfg` into R2.
   Static management IPs (.50/.51) avoid the DHCP lease changing after a reboot; keep DHCP if you prefer and just edit `host:` in `config/config.yaml`.
3. Check in VMware *Virtual Network Editor* that the vmnet8 gateway is `192.168.195.2` (change `ip route` and `ping_targets` otherwise).
   Drop the `8.8.8.8` ping target if the host has no internet.
4. Verify: `ping 192.168.195.50` from Windows, `telnet 192.168.195.50`. Tip: set **Idle-PC** on the c3745 nodes to keep CPU low.
5. `copy .env.example .env`, then **F5 → "NetCheck – GNS3 lab (no email)"**.

> Telnet is plain text – fine for a lab. For SSH: `crypto key generate rsa modulus 1024` on the routers and set `device_type: cisco_ios`, `port: 22`.

> Interface status: the c3745 has routed ports only, so it uses `show ip interface brief`. To exercise `show interfaces status`,
> add an **NM-16ESW** module to a router slot (node → Configure → Slots), add a device with `role: switch` and `checks: [ping, interfaces]`
> (not verified on 12.4; the parser reads the standard column layout).

### Try failures
| On the lab | Expected result |
|---|---|
| R2: `interface fa1/0` → `shutdown` | pings/traceroute to R2 fail, OSPF routes missing, critical interface down → **CRITICAL** |
| R1: `no ip route 0.0.0.0 0.0.0.0 192.168.195.2` | "No default route" → **WARNING** |
| Wrong `NET_PASSWORD` | "Authentication failed" → **CRITICAL** |
| Stop a node | "Timeout connecting" → **CRITICAL** |

## 3. E-mail

* **Local test**: [Mailpit](https://mailpit.axllent.org) (`mailpit` → SMTP :1025, web UI http://localhost:8025) or
  `pip install aiosmtpd && python -m aiosmtpd -n -l localhost:1025` (prints mail to console). Defaults already point to `localhost:1025`.
* **Real SMTP / Gmail**: set in `.env` `SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_STARTTLS=true SMTP_USER=… SMTP_PASSWORD=<app password> ADMIN_EMAIL=…`
  (port 465 → `SMTP_SSL=true`, `SMTP_STARTTLS=false`).
* Mail = summary text + compact HTML body + attachments (full HTML with raw output, PDF).

## 4. Scheduling

```cron
# Linux – every 30 minutes
*/30 * * * * /opt/network-health-check/.venv/bin/python /opt/network-health-check/main.py >> /opt/network-health-check/logs/cron.log 2>&1
```
```bat
:: Windows Task Scheduler – hourly
schtasks /Create /SC HOURLY /TN "NetCheck" /TR "C:\netcheck\.venv\Scripts\python.exe C:\netcheck\main.py"
```
The exit code makes it easy to chain alerts (`||` in shell, or a monitoring wrapper).

## 5. Tuning

* Thresholds: `thresholds:` (loss %, latency ms). Per device: `checks`, `ping_targets`, `traceroute_targets`,
  `expected_routes` (matched by network address), `critical_interfaces` (`Gi0/1` == `GigabitEthernet0/1`), `require_default_route`.
* Other vendors: set `device_type` (Netmiko name) and override `commands`. Parsers target Cisco IOS output.
* Secrets: keep in `.env` / environment variables, never in YAML.

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| `Timeout connecting` | Cloud bound to the wrong NIC, host-only subnet mismatch, or node still booting; raise `conn_timeout` |
| `Timeout`/login loop on Telnet | VTY must allow telnet (`transport input telnet ssh`) and `login local` with the user from `.env` |
| Traceroute flagged "did not reach" | Path breaks (`* * *` or `!H`/`!N`) or TTL exhausted – check routing on the last responding hop |
| PDF skipped | `pip install xhtml2pdf` |
| `% Invalid input` finding | Command unsupported on that platform → change `commands` or the device `role` |
