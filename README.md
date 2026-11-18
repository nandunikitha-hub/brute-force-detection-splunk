# Brute Force Attack Detection Using Splunk

**A hands-on SOC project to detect and investigate repeated failed login attempts using Splunk Enterprise.**

## About the Project

Brute force attacks are a common security threat where an attacker tries multiple passwords to gain unauthorized access to an account.

In this project, I used **Splunk Enterprise** to monitor Windows Security logs, identify repeated failed login attempts, and generate alerts when suspicious login activity was detected.

I also created a dashboard to view failed login attempts, usernames, source IP addresses, and login activity over time.

This project helped me gain practical experience in SIEM monitoring, log analysis, alert configuration, and basic security investigation.

## Project Objectives

- Monitor Windows Security Event Logs.
- Identify failed login attempts.
- Detect repeated failed login activity.
- Find the usernames and source IP addresses involved.
- Configure automated alerts in Splunk.
- Create a dashboard to monitor suspicious activity.
- Investigate failed and successful login events.

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Windows 11 | Generate login events |
| Splunk Enterprise | Log monitoring and analysis |
| Windows Security Logs | Login event data |
| SPL | Search and detection queries |

## Windows Event IDs Used

| Event ID | Description |
|---|---|
| 4625 | Failed login attempt |
| 4624 | Successful login |

## Project Implementation

### 1. Configure Windows Auditing

Enabled auditing for successful and failed login attempts to generate Windows Security events.

### 2. Collect Logs in Splunk

Configured Splunk to collect Windows Security logs and searched for login events.

### 3. Identify Failed Login Attempts

Used Event ID 4625 to find failed login attempts.

### 4. Create Brute Force Detection Query

Grouped failed login attempts by time, source IP, and username. Flagged groups with five or more attempts in a five-minute time bucket.

### 5. Configure an Alert

Created a scheduled alert in Splunk to detect matching activity every five minutes.

### 6. Build a Dashboard

Created a dashboard to display failed login activity and support investigation.

### 7. Investigate Suspicious Activity

Reviewed usernames, source IP addresses, timestamps, and login event details.

## Brute Force Detection – SPL Query

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

**How the query works:**

- Searches for failed login events.
- Extracts the username and source IP address.
- Groups events into five-minute time buckets.
- Shows groups with five or more failed attempts.

## Alert Configuration

| Setting | Configuration |
|---|---|
| Alert Name | Brute Force Attack Detection |
| Alert Type | Scheduled |
| Schedule | Every 5 minutes |
| Time Range | Last 5 minutes |
| Trigger Condition | Number of Results > 0 |
| Severity | High |
| Action | Add to Triggered Alerts |

**Result:** Successfully triggered and verified the alert in Splunk during testing.

## Splunk Dashboard

Created a dashboard with five panels to monitor and analyze login activity.

1. Total Failed Login Attempts
2. Failed Attempts by Username
3. Failed Attempts by Source IP
4. Failed Login Timeline
5. Recent Failed Login Events

The dashboard time range was set to the last seven days.

## Project Screenshots

Screenshots of the Splunk searches, detection results, alert configuration, triggered alert, and dashboard are available in the `docs/screenshots/` folder.

## Repository Structure

```text
brute-force-detection-splunk/
│
├── README.md
├── .gitignore
│
├── spl/
│   ├── 01_failed_logons.spl
│   ├── 02_brute_force_detection.spl
│   ├── 03_failed_by_username.spl
│   ├── 04_failed_by_source_ip.spl
│   ├── 05_failed_login_timeline.spl
│   ├── 06_recent_failed_events.spl
│   └── 07_failed_and_successful_logons.spl
│
└── docs/
    └── screenshots/
```

## Project Results

- Detected repeated failed login attempts in Windows Security logs.
- Identified the source IP address and usernames associated with the events.
- Successfully configured and triggered a Splunk alert.
- Created a dashboard for monitoring and investigation.
- Observed local lab activity from `127.0.0.1` during testing.

## What I Learned

- Working with Splunk Enterprise.
- Writing SPL queries for security investigations.
- Analyzing Windows Security Event Logs.
- Understanding failed and successful login events.
- Configuring scheduled alerts.
- Creating SIEM dashboards.
- Performing basic security event investigation.

## Future Improvements

- Add email notifications for triggered alerts.
- Improve detection using rolling time windows.
- Add detection for successful login after repeated failures.
- Extend monitoring to multiple systems.

## Disclaimer

This project was created in a controlled local lab environment for learning purposes. The login attempts were generated for testing and do not represent a confirmed real-world attack.

**Author:** Nandu


