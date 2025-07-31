# Microsoft-Azure-HoneyPot

# 🛡️ Azure Honeypot Project – Monitoring Attacker TTPs using Cowrie & RDP

## 📖 Project Overview

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

- Cowrie-Setup Scripts and Config for Cowrie deployment
  
- Data Collection Endpoint And Data Collection Rule

- Windows-rdp-Monitoring: RDP logging configs (e.g. Security Logs Custom XPath event forwarders)

- Microsoft Sentinel Workbook: Setting HeatMap and Related KQL Queries
- Remediation: Suggested Controls and Response Plans
- [Threat Intelligence Integration: Playbook/Logic App Designer](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/edit/main/README.md#-threat-intelligence-integration)


## 🎯 Objectives

- Deploy and monitor a honeypot on Azure
- Capture real-world attacker activity (SSH and RDP)
- Analyze logs to extract meaningful threat intelligence
- Propose remediation strategies based on industry-standard cybersecurity controls


## 🛠️ Tech Stack

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


## 🧠 Key Learnings

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

## Microsoft Azure HoneyPot Architecture

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/e8fcd6b2ca61826a076c1f79548bfae8e142387a/Azure%20honeypot%20Architecture.png)

---

## Steps

🐍 Cowrie Installation

[PowerShell: Installation and Configuration](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/instal-configure-cowrie.ps1)

Overview of cowrie installation

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/228193ee38644b4eb39045e8531e039bf44ba67a/1.png)

##


📄 View & Generate Log Data for Azure Log Analytics Workspace/ Downloaded to the Host Machine Via HTTP Sever

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

📊 Setting Up Log Analytics in Azure

Azure Log Analytics is a service that helps you collect, store, and understand all the data (logs) generated by your Azure services so you can monitor, troubleshoot, and secure your cloud environment, set up and creating log analytical workspace and creating table for custom logs. [Sample-Log-Analytics](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/log-analytics-workspace.md)

Image ref:

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/a4f3c5972f2a5e2f2153c14b68bdbb04c597cf1d/2.png)

##

## 🌐 Data Collection Endpoint (DCE)
Think of a Data Collection Endpoint (DCE) as a doorway or a specific address in Azure where data can be sent for monitoring.

Its Purpose: A DCE provides the actual network endpoint (a URL) that data sources (like the Azure Monitor Agent or custom applications using the Logs Ingestion API) use to send their monitoring data.

##

## 📥 Data Collection Rule (DCR)
A Data Collection Rule (DCR) is like a detailed instruction manual that tells Azure Monitor what data to collect, how to process it, and where to send it.

Its Purpose: DCRs define the logic for data collection. They specify:

Data Sources: What kind of data to collect (e.g., Windows Event Logs, Syslog, performance counters, custom text logs).

Filtering: Which specific events or metrics to include or exclude (e.g., only critical error events, specific performance counters). This helps reduce noise and costs.

Transformations (KQL): How to modify or enrich the data before it's stored (e.g., parse a log message, add new fields, mask sensitive information). This makes data more useful and can further reduce storage costs. 

[DCE-DCR Collection Guide](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/dce-dcr.md)

##

⚙️ Generate Events for Testing
- Simulate failed and successful login attempts on the Linux honeypot via SSH.
- Purpose: Trigger fresh log entries to test Log Analytics data flow.

##

📊 Query Cowrie Logs in Log Analytics

 -  Log Analytics Workspace → Logs
 -  Run query on custom table:
 -  CowrieLog_CL
Using Regex to create a sample query for the custom logs: As seen below

Image ref: 

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/2a98e3834cc17608c4a041193b87e60e56d3f6b7/3.png)

##

It's an excellent idea to set up alerts for successful SSH logins in honeypot! This is a classic use case: Network-T1078-SSH Successful Login Based on MITRE ATT&CK T1078 (Valid Accounts). by extension, essentially to create an Action Group for Email Notification anytime there's [Successful Login](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/setup-alert-SSH.md)

Image ref: 

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/fc6e1f14156966133987b9a2f3f00b03e64ac769/4.png)

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/fc6e1f14156966133987b9a2f3f00b03e64ac769/5.png)

---

Windows Honeypot Setup & Log Strategy

Virtual Machine Setup:
Create a Windows VM, ensuring RDP port 3389 is publicly exposed. After deployment, log in via public IP/password to configure log forwarding to Azure Log Analytics.

Log Forwarding Strategy:
To manage costs, forward only specific Security logs Event ID 4625 (logon failure), and  using custom XPath filtering. Prioritize Event ID 4624 (successful logon), specifically tracking Logon Types 7 (Workstation Unlock) and 10 (RemoteInteractive) for critical Digital Forensic Analysis.

Create Data Collection Endpoint (DCE) & Data Collection Rule (DCR). Just as it was done with the Cowrie.

```plaintext

XPath Expressions
These are used in the custom data collection rules for targeting specific RDP logon types via Event IDs:

✅ Successful RDP Logon (Event ID 4624, Logon Type 7 or 10)
*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] = '10' or Data[@Name='LogonType'] = '7']]
Log name:

Security!*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType'] = '10' or Data[@Name='LogonType'] = '7']]
❌ Failed RDP Logon (Event ID 4625)
*[System[(EventID=4625)]]
Log name:
Security!*[System[(EventID=4625)]]

```
![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/3d02ce298ca1dced0364f21791588aeea79d6c5f/8.png)

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


![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/c36d711aa3999aeb4feefd8e546e67d770c24f82/22.png)

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/5cf56c86220796ee916397d44351e031574a8886/9.png)

Save Queries
- Save 4624-based query as "Successful Windows logon".
- Save 4625-based query as "Failed Windows logon".

---

## Microsoft Sentinel Workbook:

Configuring the appropriate visualization types (especially "Map" for the IP-based queries), to have a powerful and interactive dashboard to monitor and analyze activity

[HeatMap: Map Setting & Related Kql Queries](https://github.com/SAYOOLA591/Microsoft-Azure-HoneyPot/blob/main/workbook-heatmap.md)

- Failed SSH Logon Map: Visualizes the geographic sources of failed SSH login attempts.
- Successful SSH Logon Map: Displays the geographic origins of successful SSH logins.
- Successful SSH Logon by User: Shows a breakdown of which usernames successfully logged in via SSH.
- Failed Windows Logon Map: Maps the geographic sources of failed RDP/Windows login attempts.
- Successful Windows Logon Map: Illustrates the geographic origins of successful RDP/Windows logins.
- Successful Windows Logon by User: Presents a breakdown of which usernames successfully logged into the Windows honeypot.

##

💾 Save Final Workbook
  - Name: "External Authentication Activity".
  - Save to resource group: Project.
  - Use Refresh to automatically load updated data.

Image Ref: 

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/14d3a4fa87ce0f003cb3360e1bb57299231bccdf/23.png)

---

## 🛡️ Remediation Plan NIST 800-61 Incident Handling Guide

🔐 SC-7 – Boundary Protection (NIST 800-53 Rev. 5)

| Element                | How SC-7 Applies                                                                                                                                                                        |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **External Exposure**  | honeypot simulates exposed boundaries (e.g., open SSH and RDP ports), intentionally allowing inbound connections for study.                                                        |
| **Traffic Monitoring** | log and inspect traffic to/from the honeypot to detect suspicious activity—this aligns with SC-7's focus on **monitoring boundary communications**.                             |
| **NSGs & Firewalls**   | Azure Network Security Groups (NSGs) or firewalls can simulate boundary protections—even if relaxed for honeypot purposes, they illustrate how **access would normally be restricted**. |
| **Segmentation**       | Placing honeypots in a separate virtual network or resource group prevents lateral movement, reflecting **internal boundary protection**.   

## Metrics Before Hardening / Security Controls

# 📆 Daily Honeypot Summary (24h)

**Date**: July 30, 2025  
**Controls Applied**: Geo-blocking, NSG rules, password complexity

## 🔢 Metrics Overview

| Metric | Value |
|--------|-------|
| Total login attempts | 9,035 |
| Unique source IPs | 17 |
| Successful logins | 1,556 |
| Scripts downloaded | 1 |
| Top Source Country | China |

## Attack Maps After Hardening / Security Controls

```All map queries returned no results due to no instances of malicious activity for the 24 hours after hardening.```




## Metrics After Hardening / Security Controls

| Metric | Value |
|--------|-------|
| Total login attempts | 0 |
| Unique source IPs | 0 |
| Successful logins | 0 |
| Scripts downloaded | 0 |

## 🧠 Observations

- NSG rule blocked ~70% of attempts
- Cowrie captured 1 new scripts with known malware hashes
- No successful RDP connections recorded

## 📌 Actions

- Added attacker IPs to blocklist
- Submitted samples to VirusTotal
- Will rotate honeypot passwords and monitor trends

##

## 🔎 Threat Intelligence Integration

I implemented an automated playbook for IP address enrichment using Azure Logic App Designer, integrating with third-party services such as AbuseIPDB.

- Create an account on AbuseIPDB
- Obtain your API key
- Configure an HTTP GET request in the Logic App to query the IP reputation from the API
- Refer to AbuseIPDB's API documentation for request structure and parameters

💡 Why It Matters

The goal is to transform raw IP data collected from the honeypot into actionable threat intelligence. By automating enrichment, we can quickly determine whether an IP address is associated with known malicious activity—saving time and supporting faster response decisions.

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/e3ca8422352f5ca850c3b0f91090ac241e4e842a/17.png)

![image alt](https://github.com/SAYOOLA591/HoneyPot-Images/blob/e3ca8422352f5ca850c3b0f91090ac241e4e842a/21.png)

##

```plaintext

 🧠 Threat Intelligence Enrichment

    Malicious IP Analysis
    IP: `125.40.122.202`
    GeoIP: China
    AbuseIPDB Score: 98/100
    (sshd) Failed SSH login from 125.40.122.202 (CN/China/hn.kd.ny.adsl)
```

---


## 🛡️ 🛡️ Defense-in-Depth Simulation & Gaps Analysis

Why It Matters:

This honeypot simulates a typical enterprise environment where both Cowrie (SSH) and Windows RDP services are exposed to the internet. Without proper control layering and network segmentation, such exposure could lead to real compromise.

By analyzing this setup through the lens of defense-in-depth, we can identify critical weaknesses and recommend mitigations just as a Skilled SOC analyst would in a live network. The goal is to understand what would happen if this were a real production environment and to highlight the importance of proactive security controls.

⚠️ If This Were a Real Network

- An attacker could gain initial access through exposed SSH or RDP.
- Malware could be downloaded and executed, leading to persistence or lateral movement.
- Without segmentation, the attacker could pivot deeper into the network.

## 🛡️ How Controls Could Have Helped (MITRE Mapping)

| TTP | Control that would mitigate | Active | Outcome |
|-----|-----------------------------|-----------------------------|-------|
| Initial Access (T1078) | Strong passwords, MFA | ✅ | Prevent unauthorized logins |
| Execution (T1059) Payload delivery | Application control | ✅ | Block script-based payloads |
| Persistence (T1547) | Endpoint detection (EDR) | ✅ | Detect and stop cronjob/backdoor |
| Command & Control (T1071) | Network segmentation | ✅ | Limit external callbacks |

🔍 Gaps Identified & Fixes

| Gap | Suggested Fix | 
|-----|-----------------------------|
| No brute-force protection | Enable rate-limiting or fail2ban
| Outbound traffic unrestricted | Apply NSG rules for egress filtering
| No file analysis | Add sandboxing or hash scanning on downloads
| No alerting | Integrate with Azure Monitor or a SIEM for real-time alerts

---

## 🧩 Project Conclusion:

🎯 Why This Matters

This project demonstrates how real attackers behave when given access to seemingly open systems. By analyzing their actions, we can: 

- Understand how attacks evolve
- Identify common weak points
- Strengthen real infrastructure before it’s exploited

This honeypot helps bridge the gap between theory and real-world adversary behavior.
































