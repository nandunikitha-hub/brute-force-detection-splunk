# Brute Force Attack Detection Using Splunk

A beginner-friendly SOC/SIEM lab project that uses **Splunk Enterprise** and **Windows Security logs** to detect repeated failed logon attempts.

> **Lab scope:** This project was tested in a local Windows lab. The observed source address was `127.0.0.1` (localhost). This is a simulated detection exercise, not evidence of an external attacker or a confirmed account compromise.

## Project objectives

- Collect Windows Security events in Splunk.
- Identify failed logons using Windows Event ID `4625`.
- Group failed attempts by time bucket, source IP, and account.
- Trigger an alert when the configured threshold is reached.
- Review successful logons (`4624`) during investigation.
- Visualize failed-login activity in a Splunk dashboard.

## Tools and environment

| Component | Details |
|---|---|
| Operating system | Windows 11 |
| SIEM | Splunk Enterprise |
| Splunk URL | `http://localhost:8000` |
| Index | `main` |
| Log source | Windows Security event log |
| Sourcetype used in the lab | `WinEventLog:Security` |
| Failed logon event | `4625` |
| Successful logon event | `4624` |

## How it works

1. Enable Windows logon auditing for Success and Failure.
2. Configure Splunk to ingest the Windows Security event log.
3. Generate controlled failed logon attempts in the lab.
4. Search for Event ID `4625`.
5. Group failed events into five-minute buckets by source and account.
6. Trigger a scheduled alert when five or more failures are found in a bucket.
7. Review related `4624` events and investigate the source/account context.
8. Display the results in a Splunk dashboard.

## Detection logic

The detection search uses a five-minute, clock-aligned time bucket. It is **not a rolling five-minute window**.

```spl
index=main EventCode=4625
| eval source_ip=coalesce(IpAddress,Source_Network_Address)
| eval username=coalesce(TargetUserName,Account_Name)
| where isnotnull(source_ip) AND source_ip!="-"
| bin _time span=5m
| stats count as failed_attempts by _time source_ip username
| where failed_attempts >= 5
| sort -failed_attempts
```

The threshold is configurable. In this lab, it was set to **5 failed attempts**.

## Alert configuration used

| Setting | Value |
|---|---|
| Alert name | Brute Force Attack Detection |
| Type | Scheduled |
| Schedule | Every 5 minutes (`*/5 * * * *`) |
| Search time range | Last 5 minutes |
| Trigger condition | Number of results greater than 0 |
| Trigger action | Add to Triggered Alerts |
| Severity | High |

## Dashboard panels

The Classic Dashboard was named **Brute Force Attack Detection** and included:

- Total Failed Login Attempts
- Failed Login Attempts by Username
- Failed Login Attempts by Source IP

Additional panels can be added using the searches in [`spl/`](spl/).

## Lab observations

- The dashboard showed **14 failed-login events** at the time it was checked.
- One inspected sequence contained **five failed attempts** between `02:28:41` and `02:28:56` on `16 November 2026`.
- The source address shown for those attempts was `127.0.0.1`, the loopback address.
- The alert appeared in Splunk's Triggered Alerts view during testing.
- Successful logon events were also present, but the successful events shown in the inspected sequence occurred before the five-failure sequence.

### Important investigation notes

- `127.0.0.1` is localhost; do not describe this lab result as an external IP attack.
- Windows creates background logon events for services and system accounts.
- Some extracted fields appeared duplicated or overlapped (for example, account values such as `Admin` and `WINDC$`). Validate raw event details before treating those as separate user attempts.
- A threshold alert is a signal for investigation, not proof of compromise.
- The `bin _time span=5m` command creates fixed time buckets. Attempts on opposite sides of a bucket boundary may not be grouped together.

## Repository structure

```text
brute-force-detection-splunk/
├── README.md
├── spl/
│   ├── 01_failed_logons.spl
│   ├── 02_brute_force_detection.spl
│   ├── 03_failed_by_username.spl
│   ├── 04_failed_by_source_ip.spl
│   ├── 05_failed_login_timeline.spl
│   └── 06_recent_failed_events.spl
└── docs/
    └── screenshots/
```

## Screenshots to add

Create `docs/screenshots/` and add your own screenshots, such as:

1. Windows Security event collection/input configuration.
2. Search results showing Event ID `4625`.
3. Detection search and matching result.
4. Alert configuration.
5. Triggered Alerts page.
6. Dashboard overview and panels.

Do not include real usernames, public IPs, hostnames, or other sensitive information in screenshots unless you have permission to publish them. Redact anything private.

## Limitations and future improvements

- Validate field extractions against raw Windows event details.
- Exclude known service/system accounts where appropriate.
- Consider a rolling-window detection if that behavior is required.
- Add controlled tests from a second lab host to compare local and remote source addresses.
- Enrich alerts with host, account, and network context.

## Disclaimer

This repository is for educational and authorized lab use only. Run tests only on systems and accounts you own or are explicitly authorized to assess.
