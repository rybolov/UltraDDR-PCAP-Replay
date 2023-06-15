#!/bin/python
import scapy
from scapy.all import PcapReader,rdpcap
import urllib3
import time
import datetime
import json
import argparse
import os
import re
from joblib import Parallel, delayed
import csv
import time


if not os.path.exists('config.py'):
    exit('Error, you haven\'t set up a configuration.\n\
    Please copy config.py.example to config.py and change the ClientID.')
else:
    import config
    config = config.Config()
    if config.ClientID == 'CHANGEME':
        exit('Error, you haven\'t set up a ClientID in config.py.\nPlease fix and re-run.')

generationdate = datetime.datetime.now().strftime("%Y.%m.%d %I:%M:%S %p")
today = datetime.datetime.now().strftime("%Y-%m-%d")

querytypes = {
    1 : 'A',
    2 : 'NS',
    5 : 'CNAME',
    12 : 'PTR',
    16 : 'TXT',
    28 : 'AAAA'  # ,
    # 33 : 'SRV',
    # 64 : 'SVCB',
    # 65 : 'HTTPS'
}

print('''
  _   _ _ _            ___  ___  ___  
 | | | | | |_ _ _ __ _|   \\|   \\| _ \\ 
 | |_| | |  _| '_/ _` | |) | |) |   / 
  \\___/|_|\\__|_| \\__,_|___/|___/|_|_\\ 
 | _ \\/ __| /_\\ | _ \\                 
 |  _/ (__ / _ \\|  _/                 
 |_|_ \\___/_/ \\_\\_|                   
 | _ \\___ _ __| |__ _ _  _            
 |   / -_) '_ \\ / _` | || |           
 |_|_\\___| .__/_\\__,_|\\_, |           
         |_|          |__/            
UltraDDR PCAP Replay
''')

# ----------Begin Input Validation----------


def is_valid_file(parser, filename):
    if not os.path.exists(filename):
        parser.error("The file %s does not exist!" % filename)
        quit(666)
    else:
        return filename


parser = argparse.ArgumentParser(description='Given a PCAP file, extract DNS Queries\n And send them to UltraDDR.')
parser.add_argument('-i', '--input', dest='filename', required=False, metavar='FILE',
                    help='Input file with one IOC per line.', type=lambda x: is_valid_file(parser, x))
parser.add_argument('--serial', action='store_true', help="Process in serial instead of parallel. \
This helps in troubleshooting but is slower.", default=False)
parser.add_argument('--testing', action='store_true', help="Only read the first 10 packets of the capture.",
                    default=False)
args = parser.parse_args()
# ----------End Input Validation----------


class QueryList:
    """The whole list!!!"""

    def __init__(self):
        self.queries = {}
        self.filename = ''
        self.csv = \
            [
                ['Date Generated:  ' + generationdate],
                ['Questions, comments, or complaints: contact threat-intel@vercara.com'],
                [],
                ['Query Name', 'Query Type', 'UltraDDR Status']
            ]


    def __repr__(self):
        """Return string representation of everything."""
        return json.dumps(self.__dict__, default=obj_dict, indent=4)


    def get_queries_from_file(self):
        linenumber = 0
        if not self.filename:
            exit('Error, no filename was passed.\nPlease use the -i flag to specify a file.\
            \nUse --help for more information.')
        print('Opening file:', self.filename)
        try:
            if args.testing:
                pcap = rdpcap(self.filename, 10)
            else:
                pcap = PcapReader(self.filename)
        except scapy.error.Scapy_Exception as e:
            print('Exception {}: {}'.format(self.filename, e))
            exit('Error, can\'t read PCAP file.')
        #print('File Read.\nTotal packets: {}'.format(len(pcap)))
        for pkt in pcap:
            # Opcode 0 is a query, 1 is an answer.
            if pkt.getlayer('DNS') and pkt.getlayer('DNS').opcode == 0 and pkt['DNS'].qd.qtype in querytypes.keys():
                queryname = pkt['DNS'].qd.qname.decode('utf-8').rstrip('.')
                print('Found query name: {}'.format(queryname))
                if queryname not in self.queries.keys():
                    print('Query name is unique, so adding it to our ')
                    query = Query(queryname)
                    #print(pkt['DNS'].qd.qtype.show())
                    #pkt['DNS'].qd.show()
                    if pkt['DNS'].qd.qtype != 28: # Convert AAAA to A to avoid misses.
                        query.type = querytypes[pkt['DNS'].qd.qtype]
                        print('Found query type: {}'.format(query.type))
                    else:
                        query.type = 'A'
                        print('Found query type: AAAA but changing it to A')
                    self.queries[queryname] = query
                #print(pkt['DNS'].qd.qname)
                else:
                    print('We already have this in our list, so ignoring.')
                print('')

    def makeCSV(self):
        for query in self.queries.values():
            # print(ioc)
            self.csv.append([query.queryname, query.type, query.status])
            # print(query.status)


    def get_ddr_serial(self):
        # Run twice with a 3-second pause.
        for ioc in self.queries.values():
            ioc.get_ddr()
        time.sleep(3)
        # Second Run!
        for query in self.queries.values():
            query.get_ddr()

    def get_ddr_multiprocessing(self):
        # Run twice with a 3-second pause.
        Parallel(n_jobs=5, require='sharedmem')(delayed(get_ddr_multiprocessing)(queryname)
                                                for queryname in self.queries.values())
        time.sleep(10)
        # Second Run!
        Parallel(n_jobs=5, require='sharedmem')(delayed(get_ddr_multiprocessing)(queryname)
                                                for queryname in self.queries.values())

class Query:
    """An individual FQDN, domain, or IP address"""

    def __init__(self, queryname):
        self.queryname = queryname
        self.status = ''
        self.rawresults = ''
        self.type = ''

    def __repr__(self):
        """Return string representation of Finding."""
        return json.dumps(self.__dict__, default=obj_dict, indent=4)


    def get_ddr(self):
        for looper in range(3):
            try:
                http = urllib3.PoolManager()
                queryurl = config.ProviderURL + self.queryname + '&type=' + self.type
                print(queryurl)
                req = http.request('GET', queryurl,
                                   headers={
                                       'Accept': 'application/dns-json',
                                       'X-UltraDDR-Client-id': config.ClientID
                                   }
                                   )
                ddr_results = json.loads(req.data.decode('utf-8'))
                break
            except urllib3.exceptions.NewConnectionError as e:
                print("New connection error. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.HTTPError as e:
                if re.search('certificate verify failed: unable to get local issuer certificate', e.reason):
                    print('Couldn\'t find the CA Certs, import ultraddr-ca-cert.pem and run \
                          \'<phythonhome/Install Certificates.command\'')
                print(e.reason)
                print("HTTP error. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.ConnectTimeoutError as e:
                print("Connection timed out. Resending....")
                time.sleep(looper * 2)
            except urllib3.exceptions.MaxRetryError as e:
                print("Connection timed out. Resending....")
                time.sleep(looper * 2)
            except:
                print("Connection error. Resending....")
                time.sleep(looper * 2)
        else:
            print("\n======Connection timed out.  Aborting....======\n")
        # print(json.dumps(ddr_results, indent=4))

        self.rawresults = json.dumps(ddr_results)
        if ddr_results['Status'] == 0:  # 0 means we got an answer.
            if 'Answer' in ddr_results.keys():
                print(json.dumps(ddr_results['Answer'][0]['data'], indent=4))
                if ddr_results['Answer'][0]['data'] == '20.13.128.62':
                    self.status = 'Blocked'
                    print('Blocked')
                else:
                    self.status = 'Not Blocked'
                    print('Not Blocked')
            # print(self.status)
        elif self.type =='PTR':
            self.status = 'PTR'
        elif ddr_results['Status'] == 3:  # 3 is NXDOMAIN
            self.status = 'NXDOMAIN'
        else:
            self.status = "Error"
        # print(self)

def get_ddr_multiprocessing(query):
    query.get_ddr()


def obj_dict(obj):  # Needed for the json.dumps() call in the __repr__ of the classes.
    return obj.__dict__


def main():
    fullfile = QueryList()
    fullfile.filename = args.filename
    fullfile.get_queries_from_file()
    #print(fullfile.queries.keys())
    #fullfile.get_ddr_serial()
    #fullfile.get_ddr_multiprocessing()
    if args.serial:
        fullfile.get_ddr_serial()
    else:
        fullfile.get_ddr_multiprocessing()
    fullfile.makeCSV()
    # print(json.dumps(fullfile.csv, indent=4))
    # print(fullfile)
    cvsfilename = args.filename + '-' + today + '.csv'
    with open(cvsfilename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerows(fullfile.csv)


if __name__ == "__main__":
    main()

