# ultraddr-pcap-replay

A utility that reads a packet capture (PCAP) file, extracts DNS query names, and replays them to Vercara UltraDDR using a customer account ID and gives some analysis.  It also seeds the domains/FQDNs into the Watch Engine so that they can be later qualified and blocked if they are new to UltraDDR.

This tool replays the following query types:
1. A
2. NS
3. CNAME
4. PTR
5. TXT
6. AAAA (gets converted to an A query)

Example files with DNS queries are in the testdata directory.


We give the status of each IOC:
1. Blocked: Blocked by DDR
2. Not Blocked: Not blocked by DDR
3. NXDOMAIN: The domain no longer exists or the FQDN inside of it does not exist.
4. PTR: For IP addresses, we query for PTR but UltraDDR doesn't block like it does for the other IOCs.
5. Error: Anything not in the above list


### To Use:
1. `git clone`
2. `cd UltraDDR-PCAP-Replay`
3. `python3 -m venv ./venv`
4. `source ./venv/bin/activate`
5. `pip3 install -r requirements.txt`
6. `cp config.py.example config.py`
7. `vi config.py`
6. `python3 ./ultraddr.pcap-replay.py -i testdata/dns.sample.pcap`

```commandline
python3 ./ultraddr-pcap-replay.py --help 
  _   _ _ _            ___  ___  ___  
 | | | | | |_ _ _ __ _|   \|   \| _ \ 
 | |_| | |  _| '_/ _` | |) | |) |   / 
  \___/|_|\__|_| \__,_|___/|___/|_|_\ 
 | _ \/ __| /_\ | _ \                 
 |  _/ (__ / _ \|  _/                 
 |_|_ \___/_/ \_\_|                   
 | _ \___ _ __| |__ _ _  _            
 |   / -_) '_ \ / _` | || |           
 |_|_\___| .__/_\__,_|\_, |           
         |_|          |__/            
UltraDDR PCAP Replay

usage: ultraddr-pcap-replay.py [-h] [-i FILE] [--serial] [--testing]

Given a PCAP file, extract DNS Queries And send them to UltraDDR.

options:
  -h, --help            show this help message and exit
  -i FILE, --input FILE
                        Input file with one IOC per line.
  --serial              Process in serial instead of parallel. This helps in
                        troubleshooting but is slower.
  --testing             Only read the first 10 packets of the capture.
```