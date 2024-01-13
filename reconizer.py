import requests
import json
import copy
import tldextract
import re, dns.resolver
from shodan import Shodan
import argparse
from tqdm import tqdm  # Import tqdm for the progress bar
import csv  # Import the csv module

dns_server = '1.1.1.1'

parser = argparse.ArgumentParser("prscan.py")
parser.add_argument("--hostfile", metavar='<file>', help="A txt file with hosts per newline", type=str, required=True)
parser.add_argument("--ipinfo-token", metavar='<token>', help="API token for ipinfo.com", type=str, required=True)
parser.add_argument("--output", metavar='<output>', help="Output CSV filename", type=str, default="reconizer-results.csv")  # Add a default filename

args = parser.parse_args()
hostfile = args.hostfile
apitoken = args.ipinfo_token
output_filename = args.output  # Get the specified output filename from the command line argument

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
    for i in tqdm(range(len(ips))):  # Use tqdm for the progress bar
        try:
            dnsresolver = dns.resolver.Resolver()
            dnsresolver.nameservers = [dns_server]
            dnsresolver = list(dnsresolver.resolve(domains[i], 'A'))
            ips[i] = str(dnsresolver.pop())
        except Exception as e:
            ips[i] = ""

    print()
    openPortsShodan = ips.copy()
    vulnsShodan = ips.copy()
    ipinfo = ips.copy()

    existingShodanRequest = {}
    print("[~] Analyzing ports, CVEs and IP information")
    openPortsShodan = []  # Initialize openPortsShodan outside the loop
    vulnsShodan = []  # Initialize vulnsShodan outside the loop
    for i in tqdm(range(len(ips))):  # Use tqdm for the progress bar
        if ips[i] in existingShodanRequest:
            openPortsShodan.append(existingShodanRequest[ips[i]][0])
            vulnsShodan.append(existingShodanRequest[ips[i]][1])
            ipinfo[i] = existingShodanRequest[ips[i]][2]
        else:
            if ips[i] != "":
                try:
                    # query InternetDB by shodan for CVE and port information
                    apirequest = requests.get("https://internetdb.shodan.io/{0}".format(ips[i])).json()
                    openPortsShodan.append(apirequest.get('ports', []))
                    vulnsShodan.append(apirequest.get('vulns', []))
                except:
                    openPortsShodan.append([])
                    vulnsShodan.append([])
                    
                try:
                    # query ipinfo.com API for IP information
                    ipinforequest = requests.get("https://ipinfo.io/{0}?token={1}".format(ips[i],apitoken)).json()
                    ipinfo[i] = ipinforequest
                except:
                    ipinfo[i] = ""
                
                existingShodanRequest[ips[i]] = [openPortsShodan[-1], vulnsShodan[-1], ipinfo[i]]
            
            else:
                openPortsShodan.append([])
                vulnsShodan.append([])
                ipinfo[i] = ""

    crtscan = {
        "domains": domains,
        "ips": ips,
        "openPortsShodan": openPortsShodan,
        "vulnsShodan": vulnsShodan,
        "ipinfo" : ipinfo,
    }
        
    print()
    print('ID;ROOT;DOMAIN;IP;PORTS;CVE;ASN;ORG;CITY;REGION;COUNTRY')
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

        print(f'HOST-{i};{tldextract.extract(domain.strip()).registered_domain};{domain};{ip};{ports};{cves};{asn};{organization};{city};{region};{country}')

    # Write the results to the specified CSV file
    with open(output_filename, mode='w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(['ID', 'ROOT', 'DOMAIN', 'IP', 'PORTS', 'CVE', 'ASN', 'ORG', 'CITY', 'REGION', 'COUNTRY'])

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

            csv_writer.writerow([f'HOST-{i}', tldextract.extract(domain.strip()).registered_domain, domain, ip, ports, cves, asn, organization, city, region, country])

if __name__ == '__main__':
    prscan(hostfile)
