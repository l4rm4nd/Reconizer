import requests
import json
import copy
import tldextract
import re, dns.resolver
from shodan import Shodan
import argparse

dns_server = '1.1.1.1'

parser = argparse.ArgumentParser("prscan.py")
parser.add_argument("--hostfile", metavar='<file>', help="A txt file with hosts per newline", type=str, required=True)
parser.add_argument("--ipinfo-token", metavar='<token>', help="API token for ipinfo.com", type=str, required=True)

args = parser.parse_args()
hostfile = args.hostfile
apitoken = args.ipinfo_token

def prscan(hostfile):  
    domains = []

    with open(hostfile,'r') as fin:
        lines = fin.readlines()
    for line in lines:
        domains.append(str(line).rstrip("\n"))

    # get unique hosts by converting to set and back
    domains = list(set(domains))
    ips = domains.copy()

    print("[~] DNS resolving hostnames to IP")
    for i in range(len(ips)):
        print(".", sep=' ', end='', flush=True)
        try:
            dnsresolver = dns.resolver.Resolver()
            dnsresolver.nameservers = [dns_server]
            dnsresolver = list(dnsresolver.resolve(domains[i], 'A'))
            ips[i] = str(dnsresolver.pop())
        except Exception as e:
            #print(str(e))
            ips[i] = ""

    print()
    openPortsShodan = ips.copy()
    vulnsShodan = ips.copy()
    ipinfo = ips.copy()

    existingShodanRequest = {}
    print("[~] Analyzing ports, CVEs and IP information")
    for i in range(len(openPortsShodan)):
        print(".", sep=' ', end='', flush=True)
        if ips[i] in existingShodanRequest:
            openPortsShodan[i] = existingShodanRequest[ips[i]][0]
            vulnsShodan[i] = existingShodanRequest[ips[i]][1]
            ipinfo[i] = existingShodanRequest[ips[i]][2]
        else:
            if ips[i] != "":
                try:
                    # query InternetDB by shodan for CVE and port information
                    apirequest = requests.get("https://internetdb.shodan.io/{0}".format(ips[i])).json()
                    openPortsShodan[i] = apirequest['ports']
                    vulnsShodan[i] = apirequest['vulns']
                except:
                    openPortsShodan[i] = ""
                    vulnsShodan[i] = ""
                    
                try:
                    # query ipinfo.com API for IP information
                    ipinforequest = requests.get("https://ipinfo.io/{0}?token={1}".format(ips[i],apitoken)).json()
                    ipinfo[i] = ipinforequest
                except:
                    ipinfo[i] = ""
                
                existingShodanRequest[ips[i]] = [openPortsShodan[i],vulnsShodan[i],ipinfo[i]]
            
            else:
                openPortsShodan[i] = ""
                vulnsShodan[i] = ""
                ipinfo[i] = ""

    crtscan = {
        "domains": domains,
        "ips": ips,
        "openPortsShodan": openPortsShodan,
        "vulnsShodan": vulnsShodan,
        "ipinfo" : ipinfo,
    }
        
    print()
    print('ID;DOMAIN;IP;PORTS;CVE;ASN;ORG;CITY;REGION;COUNTRY')
    for i in range(len(crtscan['domains'])):
        domain = crtscan['domains'][i]
        ip = crtscan['ips'][i]
        ports = crtscan['openPortsShodan'][i]
        cves = crtscan['vulnsShodan'][i]
        ipinfo = crtscan['ipinfo'][i]

        failstr = "N/A"

        if len(ports) == 0:
            ports = failstr
        else:
            ports = str(ports)[1:-1].replace(' ','')
        if len(ip) == 0:
            ip = failstr
        if len(ipinfo) == 0:
            asn = failstr
            organization = failstr
            city = failstr
            region = failstr
            country = failstr
        else:
            try:
                if ipinfo['org'].startswith('AS'):
                    asn = ipinfo['org'].split(" ", 1)[0]
                    organization = ipinfo['org'].split(" ", 1)[1]
                else:
                    asn = "N/A"
                    organization = ipinfo['org']
                city = ipinfo['city']
                region = ipinfo['region']
                country = ipinfo['country']
            except:
                asn = failstr
                organization = failstr
                city = failstr
                region = failstr
                country = failstr

        if len(cves) == 0:
            cves = failstr
        else:
            cves = str(cves)[1:-1].replace(' ','')

        print('HOST-'+str(i) + ';' + str(domain) + ';' + str(ip) + ';' + ports + ';' + cves + ";" + asn + ";" + organization + ";"  + city + ";" + region + ";" + country)
    
if __name__ == '__main__':
    prscan(hostfile)
