# Microsoft-Azure-HoneyPot

# Azure Honeypot Project – Monitoring Attacker TTPs using Cowrie & RDP

## Microsoft Azure HoneyPot Architecture

![image](https://private-user-images.githubusercontent.com/194605446/473813493-62612851-cead-420d-b520-a5f8a8919c85.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTE4MDcsIm5iZiI6MTc1NDI1MTUwNywicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODEzNDkzLTYyNjEyODUxLWNlYWQtNDIwZC1iNTIwLWE1ZjhhODkxOWM4NS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDA1MDdaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0zZmQ0MDc3MjFiMjYwMzU5MDVlN2M1OWRlODkzM2MyY2EwOTY2MzMwZmMxNzQyMTg3M2VhYjVmNjE4NDRjMzdhJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.e2iRW1fJypg4C0mdVmqwMo7pKYGySNVXBYdMHKeWZU8)

## Project Overview

To lure attackers, observe their TTPs (Tactics, Techniques, and Procedures), and potentially collect toolkits for analysis without putting real systems at risk. By analyzing the behavior of attackers within the honeypot, security teams can gain valuable threat intelligence, improve their defenses, and potentially prevent future attacks on critical systems. 

This project sets up a live honeypot environment in **Microsoft Azure**, exposing:
- A **Linux SSH honeypot** using [Cowrie](https://github.com/cowrie/cowrie)
- A **Windows Server RDP instance** with logging enabled

The goal is to **collect and analyze attacker techniques, tools, and procedures (TTPs)** in a controlled environment.

Key Metric Includes:

- SecurityEvent (Windows Event Logs)

- Syslog (Linux Event Logs)

- SecurityAlert (Log Analytics Workspace Alerts Triggered)

- SecurityIncident (Incidents created by Sentinel)

- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet/Network Security Groups logs)

---

## Table of Contents

- [Cowrie-Setup: Scripts and Config for Cowrie Deployment](#cowrie-setup-scripts-and-config-for-cowrie-deployment)
- [Data Collection Endpoint and Data Collection Rule](#data-collection-endpoint-and-data-collection-rule)
- [Windows-rdp-Monitoring: RDP Logging Configs](#windows-rdp-monitoring-rdp-logging-configs)
- [Microsoft Sentinel Workbook: Setting HeatMap and KQL Queries](#microsoft-sentinel-workbook-setting-heatmap-and-kql-queries)
- [Remediation: Suggested Controls and Response Plans](#remediation-suggested-controls-and-response-plans)
- [Threat Intelligence Integration: Playbook/Logic App Designer](#threat-intelligence-integration-playbooklogic-app-designer)

## Objectives

- Deploy and monitor a honeypot on Azure
- Capture real-world attacker activity (SSH and RDP)
- Analyze logs to extract meaningful threat intelligence
- Propose remediation strategies based on industry-standard cybersecurity controls


## Tech Stack

Cowrie: SSH/Telnet honeypot running on Linux

Microsoft Azure: For cloud deployment

Microsoft Sentinel: SIEM solution for monitoring

Virtual Machines: Windows Server VM with RDP exposed (for added honeypot bait)

Network Security Group (NSG)

Log Analytics Workspace

Data Collection Endpoint

Data Collection Rule (DCR)

KQL (Kusto Query Language) 

Workbook in Microsoft Sentinel

Microsoft Sentinel Playbook

Logic App Designer
##


## Key Learnings

•	Discovered brute-force attempts with common SSH usernames like ```root```, ```admin```, ```pi```

•	Observed download attempts using ```wget```, ```curl``` and script execution

•	Noticed RDP login attempts from suspicious IPs (GeoIP flagged)

•	Logged malware dropped in Cowrie’s ```downloads/``` folder for analysis

##

## Regulations

🔗 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CIS Controls v8](https://www.cisecurity.org/controls)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [NIST SP 800–61 For Incident Handling](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
##


---

## Steps

## Cowrie-Setup: Scripts and Config for Cowrie Deployment

[PowerShell: Installation and Configuration](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/instal-configure-cowrie.ps1)

Overview of cowrie installation

![image](https://private-user-images.githubusercontent.com/194605446/473813798-fca492b4-aaab-4cc1-8fe8-e7cb87102159.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTE5MzksIm5iZiI6MTc1NDI1MTYzOSwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODEzNzk4LWZjYTQ5MmI0LWFhYWItNGNjMS04ZmU4LWU3Y2I4NzEwMjE1OS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDA3MTlaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0wMWUyMDcyMDZlYzc2Y2EyYWMwMmQ0ZjczNTg0MTI5ZTU1N2FiOTRkODI2YTYxOTUxZmY2NGQxMTBjMjAzMWFkJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.YInA4VBZCpUQ_cAjVwR4sZIt94nkON2yE-WSRNOa1qg)

##


View & Generate Log Data for Azure Log Analytics Workspace/ Downloaded to the Host Machine Via HTTP Sever

[Cowrie.log: Sample & Logs Download](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/generate-logdata.md)


```plaintext
2025-07-27T17:00:02.245743Z [-] Reading configuration from ['/home/cowrie/cowrie/etc/cowrie.cfg.dist', '/home/cowrie/cowrie/etc/cowrie.cfg']
2025-07-27T17:00:02.655286Z [-] Python Version 3.12.3 (main, Jun 18 2025, 17:59:45) [GCC 13.3.0]
2025-07-27T17:00:02.655337Z [-] Twisted Version 25.5.0
2025-07-27T17:00:02.655351Z [-] Cowrie Version 2.6.1
2025-07-27T17:00:02.658522Z [-] Loaded output engine: jsonlog
2025-07-27T17:00:02.661589Z [twisted.scripts._twistd_unix.UnixAppLogger#info] twistd 25.5.0 (/home/cowrie/cowrie/cowrie-env/bin/python3 3.12.3) starting up.
2025-07-27T17:00:02.661707Z [twisted.scripts._twistd_unix.UnixAppLogger#info] reactor class: twisted.internet.epollreactor.EPollReactor.
2025-07-27T17:00:02.668844Z [-] CowrieSSHFactory starting on 2222
2025-07-27T17:00:02.669680Z [cowrie.ssh.factory.CowrieSSHFactory#info] Starting factory <cowrie.ssh.factory.CowrieSSHFactory object at 0x7378f94b7fb0>
2025-07-27T17:00:02.670148Z [-] Generating new RSA keypair...
2025-07-27T17:00:02.743904Z [-] Generating new ECDSA keypair...
2025-07-27T17:00:02.745563Z [-] Generating new ed25519 keypair...
2025-07-27T17:00:02.753361Z [-] Ready to accept SSH connections
2025-07-27T17:00:02.754104Z [-] HoneyPotTelnetFactory starting on 2223
2025-07-27T17:00:02.754238Z [cowrie.telnet.factory.HoneyPotTelnetFactory#info] Starting factory <cowrie.telnet.factory.HoneyPotTelnetFactory object at 0x7378f9007e00>
2025-07-27T17:00:02.754422Z [-] Ready to accept Telnet connections
2025-07-27T17:10:09.894773Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 2.222.94.114:57020 (10.0.0.4:2222) [session: 91a53e19110e]
2025-07-27T17:10:09.895574Z [HoneyPotSSHTransport,0,2.222.94.114] Remote SSH version: SSH-2.0-OpenSSH_for_Windows_9.5
2025-07-27T17:10:09.910004Z [HoneyPotSSHTransport,0,2.222.94.114] SSH client hassh fingerprint: 701158e75b508e76f0410d5d22ef9df0
2025-07-27T17:10:09.911028Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] kex alg=b'curve25519-sha256' key alg=b'ssh-ed25519'
2025-07-27T17:10:09.911132Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] outgoing: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-07-27T17:10:09.911201Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug] incoming: b'aes128-ctr' b'hmac-sha2-256' b'none'
2025-07-27T17:10:17.013408Z [cowrie.ssh.transport.HoneyPotSSHTransport#debug]
```
---

Setting Up Log Analytics in Azure

Azure Log Analytics is a service that helps you collect, store, and understand all the data (logs) generated by your Azure services so you can monitor, troubleshoot, and secure your cloud environment, set up and creating log analytical workspace and creating table for custom logs. [Sample-Log-Analytics](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/log-analytics-workspace.md)


![image](https://private-user-images.githubusercontent.com/194605446/473813988-b8193125-bc8e-4cc4-8895-b8f09cc0b775.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTIxMDksIm5iZiI6MTc1NDI1MTgwOSwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODEzOTg4LWI4MTkzMTI1LWJjOGUtNGNjNC04ODk1LWI4ZjA5Y2MwYjc3NS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDEwMDlaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT05OWYyNmJiZGY4YWEyODE4ZGRkNWEyNGQ2Njk5ZDc1ZjZhNDcyMjdiM2ZhZGFiNDZjNjFlODA5YWQzZmFmNGM4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.j5RdPN5Fh9picDebXVW-phQHXeq962G9sFniqoA2kv4)

---

## Data Collection Endpoint and Data Collection Rule

## Data Collection Endpoint (DCE)
Think of a Data Collection Endpoint (DCE) as a doorway or a specific address in Azure where data can be sent for monitoring.

Its Purpose: A DCE provides the actual network endpoint (a URL) that data sources (like the Azure Monitor Agent or custom applications using the Logs Ingestion API) use to send their monitoring data.

##

## Data Collection Rule (DCR)
A Data Collection Rule (DCR) is like a detailed instruction manual that tells Azure Monitor what data to collect, how to process it, and where to send it.

Its Purpose: DCRs define the logic for data collection. They specify:

Data Sources: What kind of data to collect (e.g., Windows Event Logs, Syslog, performance counters, custom text logs).

Filtering: Which specific events or metrics to include or exclude (e.g., only critical error events, specific performance counters). This helps reduce noise and costs.

Transformations (KQL): How to modify or enrich the data before it's stored (e.g., parse a log message, add new fields, mask sensitive information). This makes data more useful and can further reduce storage costs. 

[DCE-DCR Collection Guide](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/dce-dcr.md)

Azure Monitors after Linux & Windows Machine Connected to push in Logs

![image](https://private-user-images.githubusercontent.com/194605446/473814075-86ea1d3c-e169-488f-9da6-76995ff73ea2.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTIyMTQsIm5iZiI6MTc1NDI1MTkxNCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0MDc1LTg2ZWExZDNjLWUxNjktNDg4Zi05ZGE2LTc2OTk1ZmY3M2VhMi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDExNTRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xZTFhNGJhN2U2NGY2MzYzZTUyZWJmNWFkMDgzY2RkMTZhNzgzY2VlZmQ1ODI3YzNiZDVjMDZjMDgzZTllOTI5JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.UdeJbkiGeWhp3cPixMqOusUwHFqjUX8lZN4F3GprRVU)

![image](https://private-user-images.githubusercontent.com/194605446/473814135-3a7189b6-e66c-430a-a5e4-5ebbbd6af465.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTIyNDQsIm5iZiI6MTc1NDI1MTk0NCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0MTM1LTNhNzE4OWI2LWU2NmMtNDMwYS1hNWU0LTVlYmJiZDZhZjQ2NS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDEyMjRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT03MzA1YjMwY2Q4ZDg0ZjdiNGNiYjljNTZjOTdiZTE1OWVmMmZmM2E4NzBkZDk0YmI0M2MyOGIxODgyYzliN2ZlJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.GDyAoM3SbYWquS4wvB5T3c26pyGbIux4FXytB9rvO7M)

##

  Generate Events for Testing
- Simulate failed and successful login attempts on the Linux honeypot via SSH.
- Purpose: Trigger fresh log entries to test Log Analytics data flow.

##

  Query Cowrie Logs in Log Analytics

 -  Log Analytics Workspace → Logs
 -  Run query on custom table:
 -  CowrieLog_CL

![image](https://private-user-images.githubusercontent.com/194605446/473814483-5bb77a40-3fff-4103-9f70-20069630b70c.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI1NjEsIm5iZiI6MTc1NDI1MjI2MSwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0NDgzLTViYjc3YTQwLTNmZmYtNDEwMy05ZjcwLTIwMDY5NjMwYjcwYy5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDE3NDFaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1hYjliNGIxYTk5ZDRkN2Y4YzY4YTYyYTljZDQ5YWU3YzE4ZjkxZjg0ZjAxM2I1MTcyYTgzOWVhNmU1YTI3ZWNmJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.yBOfeW5_IF45g3kTxLE4WCPzEGlv12WNF5ORalrLSDI)

##

It's an excellent idea to set up alerts for successful SSH logins in honeypot! This is a classic use case: Network-T1078-SSH Successful Login Based on MITRE ATT&CK T1078 (Valid Accounts). by extension, essentially to create an Action Group for Email Notification anytime there's [Successful Login](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/setup-alert-SSH.md)
 

![image](https://private-user-images.githubusercontent.com/194605446/473814588-f2ed992a-82f8-403f-9d9f-7112574e42a9.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI2MzcsIm5iZiI6MTc1NDI1MjMzNywicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0NTg4LWYyZWQ5OTJhLTgyZjgtNDAzZi05ZDlmLTcxMTI1NzRlNDJhOS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDE4NTdaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1mNDkzOTVhZjFhMzg2YTA1ODkyYzkyYTJiZjE0YzgwZmYyMWJjMmU0NDM1NTlmZmZlN2ZjNTY5MDkxZDQwMTdhJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.zDtDYnlvAs2ly6EDBZA9E0XBXl0wK-rhGblXzdUa7UU)

![image](https://private-user-images.githubusercontent.com/194605446/473814628-2e11d658-d944-4ca2-9ea2-6958a3d7f119.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI2ODAsIm5iZiI6MTc1NDI1MjM4MCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0NjI4LTJlMTFkNjU4LWQ5NDQtNGNhMi05ZWEyLTY5NThhM2Q3ZjExOS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDE5NDBaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1jNTExOWE4MjBjYjU1ODYzYTFhY2VkZDg5OTg4NDA3ZTkzOTk2YTYxZWMyY2M4NDAzM2Y3NDcyZmJhYjE2NTQ4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.lSJxBKfkZLEbgeT29r98kU4EqC7BXcQSBrRBv0zDW0g)

---

## Windows-rdp-Monitoring: RDP Logging Configs

Windows Honeypot Setup & Log Strategy

Virtual Machine Setup:
Create a Windows VM, ensuring RDP port 3389 is publicly exposed. After deployment, log in via public IP/password to configure log forwarding to Azure Log Analytics.

Log Forwarding Strategy:
To manage costs, forward only specific Security logs Event ID 4625 (logon failure), and  using custom XPath filtering for Event ID 4624 (successful logon), specifically tracking Logon Types 7 (Workstation Unlock) and 10 (RemoteInteractive) for critical Digital Forensic Analysis.

Create Data Collection Endpoint (DCE) & Data Collection Rule (DCR). Just as it was done with the Cowrie.

```plaintext

XPath Expressions
These are used in the custom data collection rules for targeting specific RDP logon types via Event IDs:

✅ Successful RDP Logon (Event ID 4624, Logon Type 7 or 10)
Log name: Security!*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] = '10' or Data[@Name='LogonType'] = '7']]

❌ Failed RDP Logon (Event ID 4625)
Log name: Security!*[System[(EventID=4625)]]

```
![image](https://private-user-images.githubusercontent.com/194605446/473814735-42256fb3-7187-4679-a43e-4dc22403fa3f.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI3ODQsIm5iZiI6MTc1NDI1MjQ4NCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0NzM1LTQyMjU2ZmIzLTcxODctNDY3OS1hNDNlLTRkYzIyNDAzZmEzZi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDIxMjRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT02Yjg5MzMzYzk4ODk2ZjNmNjQxMThkMDM0ODI3OWIwM2NjMDdjYWEwYjI3Yjk2ODhhMGJjODg2MTc1ZGU1YjU3JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.ElS1mvyD8HryKD7vvJDmPza48ENbOUtzARAwBanhUxo)

##

These queries are used in Log Analytics to view and parse relevant RDP events.

✅ Successful RDP Logon Query (Event ID 4624)

```kql
Event 
| where EventID == 4624
|extend event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[18].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[8].["#text"])
| project TimeGenerated, Computer, username, src_ip, logontype
```


❌ Failed RDP Logon Query (Event ID 4625)

```kql
Event 
| where EventID == 4625
| extend event = parse_xml(EventData)
| extend src_ip = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[19].["#text"])
| extend username = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[5].["#text"])
| extend logontype = tostring(parse_json(tostring(parse_json(tostring(parse_json(tostring(event.DataItem)).EventData)).Data))[10].["#text"])
| project TimeGenerated, Computer, username, src_ip, logontype
```


![image](https://private-user-images.githubusercontent.com/194605446/473814911-23a258d4-6987-4b57-8255-f1f73cb63a81.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI5NTQsIm5iZiI6MTc1NDI1MjY1NCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0OTExLTIzYTI1OGQ0LTY5ODctNGI1Ny04MjU1LWYxZjczY2I2M2E4MS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDI0MTRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT00ZjZjZTU1OTVhZWZmZGQyODMxMGRmM2UzNTcwNTAxYzRlOTU2YmY4YmVmNDk4MjM2MTg4N2MwN2ZlYzJhNTliJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.2LLrC_Rv0sMtq6Z39OxsoHXpMu1WYfHve5KCSyikuxE)

![image](https://private-user-images.githubusercontent.com/194605446/473814960-9650f539-2f98-4bb2-a0bb-dc4a5298eb2e.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTI5OTQsIm5iZiI6MTc1NDI1MjY5NCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE0OTYwLTk2NTBmNTM5LTJmOTgtNGJiMi1hMGJiLWRjNGE1Mjk4ZWIyZS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDI0NTRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1iZWQyMWE2MmYwNDI5MjRjOTFhZGRkNjhkNDU2NjQ1NzNlOTk0Y2I0MGEyNWFhMGEwM2RmNDgzMmI3MDc4MmI2JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.kEJKUkf6Kk-mwisA3duRQ5-i74yfonGvFsWVV3TZ6QM)

 Save Queries
- Save 4624-based query as "Successful Windows logon".
- Save 4625-based query as "Failed Windows logon".

---
## Microsoft Sentinel Workbook: Setting HeatMap and KQL Queries

Configuring the appropriate visualization types (especially "Map" for the IP-based queries), to have a powerful and interactive dashboard to monitor and analyze activity

[HeatMap: Map Setting & Related Kql Queries](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/workbook-heatmap.md)

- Failed SSH Logon Map: Visualizes the geographic sources of failed SSH login attempts.
- Successful SSH Logon Map: Displays the geographic origins of successful SSH logins.
- Successful SSH Logon by User: Shows a breakdown of which usernames successfully logged in via SSH.
- Failed Windows Logon Map: Maps the geographic sources of failed RDP/Windows login attempts.
- Successful Windows Logon Map: Illustrates the geographic origins of successful RDP/Windows logins.
- Successful Windows Logon by User: Presents a breakdown of which usernames successfully logged into the Windows honeypot.

##

 Save Final Workbook
 - Name: "External Authentication Activity".
 - Save to resource group: Project.
 - Use Refresh to automatically load updated data.

![image](https://private-user-images.githubusercontent.com/194605446/473815126-75825a78-e62e-4b35-ae7a-f1e3acdc8cbc.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTMxNjQsIm5iZiI6MTc1NDI1Mjg2NCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE1MTI2LTc1ODI1YTc4LWU2MmUtNGIzNS1hZTdhLWYxZTNhY2RjOGNiYy5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDI3NDRaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT04YjllNjNmZDllOGZhNzg5ZjY1ZGExY2JiYzU2ZGQxYzc5ZDhmZGNkN2U5MjUzMDcxZjk5ZTM2MjNiZWU3NzIxJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.rBVeMZdb7fWzuvf4pMtpjXhQv92JLitaItWEmTv4c_M)

![image](https://private-user-images.githubusercontent.com/194605446/473815147-7f5f0248-d9be-4099-a3f4-ff37720aed79.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTMxOTMsIm5iZiI6MTc1NDI1Mjg5MywicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE1MTQ3LTdmNWYwMjQ4LWQ5YmUtNDA5OS1hM2Y0LWZmMzc3MjBhZWQ3OS5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDI4MTNaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT01MGMwZWRlOTczMDJmOGJhNGY5MDQxZmZmNzE0MjlmOGFiMDNlMzAzZjYyY2YwMjQ2MzJlYWUxNGE2ZTVmMzkxJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.D4Wshees_PFsnDZeL12QIWHH65thg3s8FX4xM1_i0UI)

![image](https://private-user-images.githubusercontent.com/194605446/473815169-eee17dfe-fd99-44f1-af32-7e0f477ee3bb.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTMyMjMsIm5iZiI6MTc1NDI1MjkyMywicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE1MTY5LWVlZTE3ZGZlLWZkOTktNDRmMS1hZjMyLTdlMGY0NzdlZTNiYi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDI4NDNaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0wMzU1MjdiYjhiZTQ3YjU2MjNlMjM0MThlNTFjOTVlNjFmMjNkYzE1MmJlM2ExYjE0OWViOGJiNGQ2NjU2MTMzJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.o1qQsAZt-mi0HG7S34TzB34NomCN4z2gfjfQ10NUNvQ)



---
## Remediation: Suggested Controls and Response Plans

SC-7 – Boundary Protection (NIST 800-53 Rev. 5)

| Element                | How SC-7 Applies                                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **External Exposure**  | honeypot simulates exposed boundaries (e.g., open SSH and RDP ports), intentionally allowing inbound connections for study.                                                        |
| **Traffic Monitoring** | log and inspect traffic to/from the honeypot to detect suspicious activity—this aligns with SC-7's focus on **monitoring boundary communications**.                             |
| **NSGs & Firewalls**   | Azure Network Security Groups (NSGs) or firewalls can simulate boundary protections—even if relaxed for honeypot purposes, they illustrate how **access would normally be restricted**. |
| **Segmentation**       | Placing honeypots in a separate virtual network or resource group prevents lateral movement, reflecting **internal boundary protection**.   

## Metrics Before Hardening / Security Controls

 Overrall Honeypot Summary

**Date**: July 30, 2025  

## Metrics Overview

| Metric | Value |
|--------|-------|
| Total login attempts | 9,035 |
| Unique source IPs | 17 |
| Successful logins | 1,556 |
| Scripts downloaded | 1 |
| Top Source Country | China |

## Attack Maps After Hardening / Security Controls

```All map queries returned no results due to no instances of malicious activity for the 24 hours after hardening.```

 Honeypot Summary (24h) After

**Date**: July 31, 2025

**Controls Applied**: Geo-blocking, NSG rules, password complexity

## Metrics After Hardening / Security Controls

| Metric | Value |
|--------|-------|
| Total login attempts | 0 |
| Unique source IPs | 0 |
| Successful logins | 0 |
| Scripts downloaded | 0 |

---
## Threat Intelligence Integration: Playbook/Logic App Designer

I automate threat enrichment by building a Logic App playbook triggered by incident creation. This playbook extracted IP addresses from incidents and sent them to the AbuseIPDB API. The response included fields like abuse confidence score, ISP, and domain, which we used to assess the reputation of the IP. The playbook then posted this information back to the incident as a comment in Microsoft Sentinel. This helped analysts quickly determine whether the IP was linked to malicious behavior.

---

![image](https://private-user-images.githubusercontent.com/194605446/473815245-998a7ba0-bbd5-4bc3-bcb8-26954f8f89bf.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTMzMDAsIm5iZiI6MTc1NDI1MzAwMCwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE1MjQ1LTk5OGE3YmEwLWJiZDUtNGJjMy1iY2I4LTI2OTU0ZjhmODliZi5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDMwMDBaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT01MDdlN2RmOWQ0ZWQ3OTAxOGViN2Y4ODJiZGY4M2RkYTQ1MGQ2Y2UxODE1NTYwN2UyYTdiMjQxOWU3ZDIxNTg1JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.zSkFPq13onKv0A1AZrsGbLC8xZyxr-r4nqBerInIRY4)

![image](https://private-user-images.githubusercontent.com/194605446/473815276-f58f1105-3058-4292-b9c1-6b0ed0becbec.png?jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTQyNTMzNjYsIm5iZiI6MTc1NDI1MzA2NiwicGF0aCI6Ii8xOTQ2MDU0NDYvNDczODE1Mjc2LWY1OGYxMTA1LTMwNTgtNDI5Mi1iOWMxLTZiMGVkMGJlY2JlYy5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjUwODAzJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI1MDgwM1QyMDMxMDZaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT1iZGQxY2YyNjkzMWZmMDY1ZDc5OTlmZmI5ODYyNjIzNTRhM2JkYWI1ZDc1ZWNkZWZlOTYwZDYwZjE1N2VmMWY4JlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCJ9.7ksTYPaNhGVFRKfe2wW3a-Y0BH4mTNOJFhYw06OMZvA)

##

```plaintext

    Threat Intelligence Enrichment

    Malicious IP Analysis
    IP: `125.40.122.202`
    GeoIP: China
    AbuseIPDB Score: 98/100
    (sshd) Failed SSH login from 125.40.122.202 (CN/China/hn.kd.ny.adsl)
```

---

## Project Conclusion:

In this project, we've created a Linux Honeypot and a Windows Server exposed to the internet. We ingested logs into our log analytics workspace, we created an alert for it and also integrated Microsoft Sentinel. We made a workbook and developed a playbook that runs on any newly triggered incidents. Essentially, in an enterprise environment, if an analyst examines an incident and has AbuseIPDB playbooks with enriched comments, it will save a significant amount of time down the road.

Finally, it is up to us again to decide how we want to build out our playbooks and the kind of workflow that would work better for our organisation. We demonstrate how real attackers behave when given access to seemingly open systems. By analysing their actions, we can understand how attacks evolve, identify common vulnerabilities, and strengthen real-world infrastructure. This honeypot helps bridge the gap between theory and real-world adversary behaviour.
































