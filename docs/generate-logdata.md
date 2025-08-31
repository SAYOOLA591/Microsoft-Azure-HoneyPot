# View & Generate Log Data 
Log files stored under /home/cowrie/var/log/cowrie/

cowrie.log – General log

Generate login attempts:

Use fake SSH attempts to produce logs

Login as root via:  ssh root@<IP> -p 2222

# Download Logs via HTTP Server

From Cowrie log directory, run:  python3 -m http.server 9999

Add port 9999 to NSG rules On host machine, open browser:

http://<public></public> IP>:9999    Download cowrie.json log file for analysis
