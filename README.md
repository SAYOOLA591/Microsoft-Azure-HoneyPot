# Microsoft-Azure-HoneyPot

# 🛡️ Azure Honeypot Project – Monitoring Attacker TTPs using Cowrie & RDP

## 📖 Project Overview

To lure attackers, observe their TTPs (Tactics, Techniques, and Procedures), and potentially collect toolkits for analysis without putting real systems at risk. By analyzing the behavior of attackers within the honeypot, security teams can gain valuable threat intelligence, improve their defenses, and potentially prevent future attacks on critical systems. 

This project sets up a live honeypot environment in **Microsoft Azure**, exposing:
- A **Linux SSH honeypot** using [Cowrie](https://github.com/cowrie/cowrie)
- A **Windows Server RDP instance** with logging enabled

The goal is to **collect and analyze attacker techniques, tools, and procedures (TTPs)** in a controlled environment.


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


🧠 Key Learnings

•	Discovered brute-force attempts with common SSH usernames like root, admin, pi

•	Observed download attempts using wget, curl and script execution

•	Noticed RDP login attempts from suspicious IPs (GeoIP flagged)

•	Logged malware dropped in Cowrie’s downloads/ folder for analysis



![image alt](https://github.com/mullarcyber/Arkime-images/blob/36e28a5cdc862881e7c6d63fe39ffa63d0eea830/1.png
)










