# SentinelAI 0.6.0 — local AI assistant

**AI Bot:** Open **AI BOT / Туслах** to chat in Mongolian about a selected alert, stored log evidence and timeline using a local Ollama LLM. Requires Ollama and a separately installed model. No model is bundled; unavailable models produce a clear error. Detection remains rule-based. See [AI_BOT.md](AI_BOT.md) for setup and limits.

**New:** Suricata EVE `alert`/TCP-UDP `flow` import; persisted normalized event references; offline Mongolian explanations using the stored rule/threshold/window/log IDs; incident timelines grouped by source/target/time; and on-demand AbuseIPDB/VirusTotal public-IP reputation with provider reason, source and separate provider/fetch timestamps. Select an alert and use **Investigate / Шинжлэх**. Run `Start-Investigation-Demo.bat` for the synthetic 15-event, 4-alert chain. See [INVESTIGATION.md](INVESTIGATION.md) for API key configuration, cache/unknown states, data disclosure, limits and commands. Explanations are offline deterministic evidence summaries, not LLM output. Live reputation APIs have not been exercised here because no keys are configured.

**New: IP/port filters and offline tool interoperability.** Use **Filters → IP / ports / protocol…** for source/destination IP or CIDR, destination port/list/ranges, TCP/UDP and telemetry-source filters. Open **Tools** for Nmap XML inventory, Wireshark/TShark CSV and Zeek JSON conn.log imports. `Start-Tools-Demo.bat` runs the new 50-source-IP, 85-packet scenario, including a Wireshark-compatible synthetic PCAP and Nmap inventory. Expected packet analysis: five port-scan indicators; Nmap inventory is not treated as an attack. See [INTEGRATIONS.md](INTEGRATIONS.md) for supported formats, commands, mature-project sources and limitations.

**Attack/risk classification and filtering:** choose **Attack / risk** in the dashboard to show SSH brute force, port scanning, suspicious login, Wi-Fi security risk, Wi-Fi network change, or other/unclassified alerts. This combines with severity and review-status filters. CSV/JSON exports include `attack_type`, `attack_label` and `classification` and contain only the displayed matches. Existing databases are classified from their rule names without rewriting alert history. CLI example: `python -m sentinelai alerts --attack-type port_scan --severity medium --export scans.csv`. These are rule-derived indicators, not confirmed attacks or ML predictions; Wi-Fi settings and network changes are explicitly classified separately.

**New: real Windows Public Wi-Fi monitoring.** Open `Start-Public-WiFi.bat` or click **Public Wi-Fi**. This reads the connected adapter's WLAN security and network configuration, evaluates open/legacy encryption and profile/firewall settings, and flags same-SSID gateway/DNS/AP changes. It performs no network scans, packet interception or system changes. Collection runs in a background worker, every 30 seconds, so the desktop remains responsive. Use `python -m sentinelai wifi --once --json` for one structured snapshot. Wi-Fi alerts and last-known baselines persist separately in `wifi-alerts.sqlite3` under your user data folder.

Read [PUBLIC_WIFI.md](PUBLIC_WIFI.md) for setup, permissions, rules and limitations (Mongolian). Windows may require Location consent for WLAN APIs. Missing or denied telemetry is explicitly shown as unavailable/partial; no “safe” verdict is inferred from zero alerts. The native host probe in this development sandbox returned Access Denied; live hotspot collection and attack detection accuracy have not been validated here.

Version 0.2.4 fixes Access Denied errors when a launcher starts in `C:\Windows\System32` or another protected folder. Default logs, simulations and alert databases now use `%LOCALAPPDATA%\SentinelAI` on Windows, or `~/.sentinelai` elsewhere. No administrator privileges are required. Explicit `--db` and `--directory` options still use your chosen paths. Advanced users can set `SENTINELAI_DATA_DIR` to an absolute writable folder. Existing files are not moved or deleted: select your previous database to review older alerts. Close previous versions and extract this release into a new folder before starting it.

Version 0.2.3 introduces a dark operations dashboard with cyan/violet accents, a live mode indicator, event counts, visible-alert counters and dark severity colors. The detection and review workflow remains shared with the terminal interface.

Version 0.2.2 fixes live-table rebuilding and scroll/selection disruption, immediately removes reviewed alerts from incompatible status filters, resets demo filters, and places controls on separate rows for smaller windows. Text wraps with the window and the table supports horizontal scrolling. Close older SentinelAI windows and extract this release into a new folder before opening its launcher.

SentinelAI is a working local application for monitoring normalized security logs, detecting three suspicious event patterns, and reviewing persistent alerts. The desktop and terminal share the same Python engine and SQLite database. No account, cloud service, GPU, runtime package downloads, or third-party Python dependencies are required.

## Open the application

On Windows, extract the release ZIP and double-click **Start-SentinelAI.bat**. Python 3.10 or newer must be installed with Tcl/Tk and available as `python`. Standard python.org Windows installations include Tcl/Tk. This is a Python application, not a standalone Windows executable.

From the source folder:

```powershell
python -m sentinelai gui
```

The release also includes **SentinelAI.pyz**, a single-file package containing all application code. It works independently of the source folder:

```powershell
python SentinelAI.pyz gui
python SentinelAI.pyz demo
```

Running the `.pyz` without arguments opens the desktop. Other operating systems can use the terminal commands with Python 3.10+; desktop use additionally requires Tk and a graphical session.

## Desktop workflow

### Live simulation

For the **50-IP example**, double-click **Start-50-IP-Demo.bat**, or click **50-IP demo** in the desktop. This version runs in approximately 12 seconds and uses exactly `192.0.2.1` through `192.0.2.50`:

| Sources | Simulated behavior | Expected alerts |
| --- | --- | --- |
| `192.0.2.1`–`192.0.2.5` | Five SSH failures, then a successful login, per IP | 5 brute-force + 5 suspicious-auth alerts |
| `192.0.2.6`–`192.0.2.10` | Eight destination ports per IP | 5 port-scan alerts |
| `192.0.2.11`–`192.0.2.50` | Normal successful logins | 0 alerts |

All 50 sources first send a normal login. The complete example contains **120 events and 15 expected alerts**, involving 10 suspicious and 40 normal sources. Addresses are synthetic examples; the application writes local logs only. Each report includes the observed IP count and validates both alert rules and source addresses.

```powershell
python -m sentinelai simulate --gui --hosts 50
python -m sentinelai simulate --hosts 50 --interval 0.05
python -m sentinelai monitor examples/simulation_50_ips.jsonl --db fifty-example.sqlite3
```

`examples/ips_50.txt` lists the 50 addresses. `examples/simulation_50_ips.jsonl` is the reusable event feed. Regenerate both with `python tools/make_50_ip_example.py`. Every simulation run also saves its own `ips.txt` alongside its reports. The CLI defaults to the original 6-IP scenario; `--hosts 50` selects this larger example.

Double-click **Start-Demo.bat** to open the dashboard and automatically run a live simulation. You can also click **Live simulation** in the application, or run:

```powershell
python -m sentinelai simulate --gui
python -m sentinelai simulate --interval 0.5
```

The simulation appends 19 synthetic events one at a time over approximately 9 seconds: normal logins, five SSH failures, a successful login after those failures, eight distinct destination ports, and normal traffic again. Watch the stage indicator and alert table. Exactly three alerts are expected: SSH brute force, suspicious authentication and port scan. The normal stages produce no alerts. This writes local files only and sends no network traffic.

Each run creates a fresh `simulation-...` under your user data folder directory containing the JSONL feed, SQLite alerts, CSV/JSON exports and `report.json` with expected versus observed rules. The dashboard stops feeding automatically on completion; the alerts remain available for review. **Stop** ends a simulation early; **Live simulation** starts a new run. The terminal accepts `--interval 0` for an immediate run and `--directory PATH` to choose the output parent. The desktop uses a fixed half-second event interval. The simulation uses default thresholds, independent of any selected configuration.

1. Click **Try synthetic demo** for an immediate walkthrough. It creates a fresh demo log and database under your user data folder, processes 14 events, and shows three alerts.
2. For your own data, choose a JSONL log, an alert database, and optionally a rules configuration file. Leave **Follow new records** enabled for live monitoring, then click **Start monitoring**. Disable it for a one-time scan.
3. Filter alerts by severity or review status. Select a row to inspect its count and detection-window evidence. **Acknowledge**, **Dismiss**, and **Mark new** persist review status in SQLite; they do not change detection.
4. **Export visible alerts** saves CSV or JSON. The table and export include up to the latest 1,000 matching alerts. Use the CLI `--limit` option for larger exports.
5. Click **Stop** before changing the log, database, or rule file. Start reconstructs windows by rereading the current log. Existing alerts remain deduplicated.

The desktop defaults to your user data folder (`%LOCALAPPDATA%\SentinelAI` on Windows). Monitoring counters describe the current run; table rows include stored history. No automatic blocking or remote notifications occur.

## Terminal workflow

Run from the source folder, or replace `python -m sentinelai` with `python SentinelAI.pyz`:

```powershell
# Generate a demo and detect its events. Reusing this directory deduplicates alerts.
python -m sentinelai demo --directory demo-run

# Follow a real normalized JSONL feed; Ctrl+C stops cleanly.
python -m sentinelai monitor examples/live.jsonl --follow --config config.json --db alerts.sqlite3

# Review, acknowledge, and export.
python -m sentinelai alerts --db alerts.sqlite3
python -m sentinelai triage 1 acknowledged --db alerts.sqlite3
python -m sentinelai alerts --db alerts.sqlite3 --status new --json
python -m sentinelai alerts --db alerts.sqlite3 --severity critical --limit 10000 --export critical.csv
```

`--color auto|always|never` controls terminal colors. `--poll 0.5` controls follow polling in seconds. `--help` documents each command. `terminal_preview.py` remains a compatibility entry point into this same CLI. Optional installation with `python -m pip install .` adds a `sentinelai` command; source and `.pyz` execution need no installation or network access.

## JSONL input

One UTF-8 JSON object per line, terminated by a newline. For example:

```json
{"timestamp":"2026-10-20T12:00:00Z","event_type":"auth","src_ip":"192.0.2.10","username":"demo","service":"ssh","outcome":"failure"}
{"timestamp":"2026-10-20T12:00:01Z","event_type":"connection","src_ip":"198.51.100.20","dst_port":443}
```

Every event needs a timezone-aware ISO 8601 `timestamp`, an IPv4/IPv6 string `src_ip`, and `event_type` (`auth` or `connection`). Auth events require a nonempty `username` and `outcome` (`success` or `failure`); `service: "ssh"` selects SSH detection. Connection events require integer `dst_port` in 1–65535. IPs are canonicalized. Additional fields are allowed. Malformed records are skipped and counted.

To append from a second PowerShell terminal:

```powershell
'{"timestamp":"2026-10-20T12:00:00Z","event_type":"auth","src_ip":"192.0.2.10","username":"demo","service":"ssh","outcome":"failure"}' | Add-Content -Encoding utf8 examples/live.jsonl
```

Follow mode waits if the log does not exist yet, reads existing content first, then consumes appended complete lines. Unfinished records remain pending, including a final line without a newline in one-time scans. Truncation and file replacement reset the reader. A content anchor detects most truncate-and-regrow cases; identical prefixes may conceal a rewrite, and unread bytes from an old rotated file can be lost. This polling reader is not a lossless log shipper.

Events must arrive in nondecreasing timestamp order across the stream. Older events are dropped and counted as `late`. Detection uses inclusive event-time windows, not machine time. Raw sshd/syslog text and CSV require an upstream normalization adapter.

## Detection and configuration

Edit `config.json` and select it in the desktop or pass `--config`. Partial configurations inherit defaults; invalid keys and nonpositive/noninteger settings fail before monitoring.

| Rule | Default trigger per source IP | Base score |
| --- | --- | --- |
| SSH brute force | 5 failed SSH authentications in 60 seconds | 65 |
| Port scan | 8 distinct destination ports in 30 seconds | 50 |
| Suspicious authentication | A successful authentication following 3 auth failures in 300 seconds | 80 |

Port counts aggregate destinations. Suspicious authentication aggregates usernames and services per source. These choices make NAT, shared networks, legitimate retries, and authorized scanners possible false positives. A suspicious authentication sequence is a review signal, not proof of compromise.

Scores add 5 per count beyond threshold, capped at 100. Severity is medium below 70, high at 70–89, critical at 90+. Scores are deterministic priorities, not probabilities. Same-rule/source alerts are suppressed through one full rule window after the last stored alert, inclusively. Suppression survives restarts and review-status changes; suppressed evidence does not update an old alert. A unique fingerprint provides additional duplicate protection.

## Storage and compatibility

SQLite stores alert ID, timestamp, rule, source IP, severity, score, evidence and review status. Existing v0.2 databases receive the status column and lookup index automatically, preserving alerts. Back up an existing database before opening it with a new release; stop monitoring before copying it. Keep databases and logs in an access-controlled location.

Offsets and active windows are in memory. Restart rereads the current file and suppresses stored alerts; historical context cannot be recovered if the log has already rotated away. Use one monitor per database. Alert history has no automatic deletion policy. Review/export commands require an existing database.

## Verify and build

```powershell
python -m unittest discover -s tests -v
python tools/smoke_desktop.py
python tools/verify_release.py
```

The release script runs tests and a real Tk widget smoke check, records actual output in `VERIFICATION.txt`, builds `dist/SentinelAI.pyz`, runs that portable file from an isolated working directory, packages the source and launcher, checks ZIP integrity, and writes SHA-256 checksums. A graphical session with Tk is required for the desktop smoke check. The source ZIP excludes runtime databases and user logs.

Tests cover live partial writes, malformed input, rule thresholds, inclusive boundaries, expiry, source isolation, unique ports, auth correlation, risk scoring, restart deduplication, late events, truncation/replacement, existing database migration, review status, filtered export, and CLI integration.

## Product scope

This release is a local, rule-based monitoring tool for modest log volumes. It is not a trained AI model or an enterprise SIEM. The original v0.1 files and train/validation/test CSVs were unavailable; the included fixtures were generated synthetically. No real-world precision, recall, or accuracy has been measured.

The reader and detector operate in memory; large files, huge lines or high event rates can exhaust memory or delay the desktop. Durable event queues, log adapters, agent deployment, remote collection, tamper protection, automated response and service supervision are outside this release. The application evaluates trusted normalized telemetry. Streamlit is unnecessary for this release because the desktop UI uses the standard library.

## Code layout

| Component | Purpose |
| --- | --- |
| `sentinelai/core.py` | Input validation, detection, SQLite and incremental reader |
| `sentinelai/service.py` | Shared monitoring lifecycle and export |
| `sentinelai/gui.py` | Desktop monitoring and alert review |
| `sentinelai/__main__.py` | Terminal commands and desktop entry point |
| `sentinelai/demo.py` | Shared synthetic demo generator |
| `tools/verify_release.py` | Verified portable and source packaging |

If launch fails, check `python --version` and `python -m tkinter`. If no records appear, check the final newline, input schema and timestamp order. If replay emits no new alerts, review the stored database: deduplication is expected.
