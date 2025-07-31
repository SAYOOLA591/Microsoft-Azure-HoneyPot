Install

Run system updates: sudo apt-get update && sudo apt-get upgrade -y
Add a Cowrie user: sudo adduser --disabled-password cowrie
Switch to Cowrie user and navigate to home:  sudo su cowrie
cd /home/cowrie 
Clone Cowrie GitHub repo: git clone https://github.com/cowrie/cowrie
ls and cd cowrie

Dependencies

sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install git python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal authbind
Setup Python Virtual Environment

Create and activate venv:  python3 -m venv cowrie-env
source cowrie-env/bin/activate
Upgrade pip and install requirements: python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

Cowrie Configuration

Create a new config file: cd etc :  ls

nano cowrie.cfg     Add: [telnet] enabled = true

Save file and start Cowrie:  cd ..   

cd bin

./cowrie start

Note: Cowrie Listening on Port 2222


