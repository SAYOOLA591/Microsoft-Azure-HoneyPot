# Create Data Collection Endpoint
  
  Search for Data Collection Endpoints in Azure.
  Click "Create" and assign it to the same Resource Group.
  Name it (e.g., LinuxMachine). Review + Create

# Create Data Collection Rule (DCR)
  Search for Data Collection Rules → Click Create:
  Rule name: e.g., CollectCowrie Platform: Linux
  Select the previously created Data Collection Endpoint
  
  Under Resources:  Add your Linux Honeypot VM

  Add Data Source:
  Type: Custom Text
	
  File path: Same path as earlier ``(e.g., /home/cowrie/var/log/cowrie/cowrie.log)``
  Table name: e.g., ``CowrieLog_CL``
  Transform: source
	
  Set Destination: Type: Azure Monitor Logs   Workspace: select the Log Analytics Workspace

  Review + Create

# Verify Integration & Data Ingestion

  Navigate back to Log Analytics Workspace:  Under Agents, check Linux OS → Wait for heartbeat signal.
 
  Once Linux VM shows as connected, Go to the Logs tab.  
  Query the custom table: ```CowrieLog_CL```
  Note: Data may not appear immediately. It takes time for the endpoint to ingest and push logs.

  Extras & Notes
  Use KQL (Kusto Query Language) to query and analyze log data.
  
  Azure provides built-in queries and KQL training under the Logs section.
  
  Custom table name should always end in _CL ```(for "Custom Log")```
