# Microsoft-Azure-HoneyPot


## 📂 Project Structure

```plaintext
honeypot-azure/
├── cowrie-setup/           # Scripts and config for Cowrie deployment
├── windows-rdp-monitoring/ # RDP logging configs (e.g. Sysmon, event forwarders)
├── logs-samples/           # Sanitized samples of attacker activity
├── ttp-analysis/           # Analysis reports on TTPs
├── remediation/            # Suggested controls and response plans
├── screenshots/            # Attack session screenshots and dashboards

## 🛠️ Tech Stack

| Component | Description |
|----------|-------------|
| **Cowrie** | SSH & Telnet honeypot for simulating shell environments |
| **Azure VM (Ubuntu)** | Host for Cowrie, publicly exposed port 22 |
| **Azure VM (Windows Server)** | Public RDP access with auditing enabled |
| **ELK Stack / Azure Monitor (Optional)** | For centralized log analysis and visualization |
