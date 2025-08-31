# Setting Up Log Analytics in Azure

Purpose: To query Cowrie logs ``(e.g., cowrie.log)`` using Azure Monitor and KQL

Tool: Azure Log Analytics workspace

# Create Log Analytics Workspace

Go to Azure portal → search for Log Analytics

Click Create, select the existing Resource Group (e.g., Project)

Name the workspace (e.g., ProjectHoneypot) → Review + Create

# Create a Table for Custom Logs

Go to the created Log Analytics Workspace → under Settings, select Tables

Click Create:  Choose MMA (legacy method), not DCR (due to limitations)

Upload the ``cowrie.log`` file as a sample.

Set:
Delimiter: Automatically detected

OS: Linux.    Log file path: Use PWD from PowerShell ``(e.g., /home/cowrie/var/log/cowrie/)``
Table name: e.g., ``CowrieLog_CL``

After creation:
Click the 3 dots beside the table → Edit Schema → Migrate to Manual Schema Management
