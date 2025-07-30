# Create Alert Rule for SSH Successful Login
  
  Identify the event ID for login success (cowrie.login.success)
  
  Add where eventID == ``cowrie.login.success`` to your query
  
  Create a new alert rule:
  
  Signal: Custom log search
  
  Frequency: Every 5 minutes
  
  Trigger Condition: When result count > 0

# Create an Action Group:

  Name: e.g., Notification
  
  Notification type: Email
  
  Use a disposable or preferred email address

# Configure Alert Details

  Severity: Informational
  
  Name format: ``Network-T1078-SSH Successful Login``
  
  Based on MITRE ATT&CK T1078 (Valid Accounts)

# Expose Linux Honeypot to the Internet
  
  Modify Network Security Group (NSG):
  
  Set source IP to Any
 
  Port range to *
  
  Protocol to Any
  
  This allows attackers worldwide to connect to the honeypot on port 2222.

