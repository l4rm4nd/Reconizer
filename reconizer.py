import asyncio
import dns.resolver
import requests
import json
import csv
import copy
import tldextract
import re, dns.resolver
import argparse
from shodan import Shodan
from datetime import datetime


# specify dns server to use
dns_server = '1.1.1.1'

# specify output filename
date = datetime.now().strftime("%Y%m%d-%H%M")
outfile = date + "_Reconizer" + ".csv"

# argparse
parser = argparse.ArgumentParser("prscan.py")
parser.add_argument("--hostfile", metavar='<file>', help="A txt file with hosts per newline", type=str, required=True)
parser.add_argument("--ipinfo-token", metavar='<token>', help="API token for ipinfo.com", type=str, required=True)

args = parser.parse_args()
hostfile = args.hostfile
apitoken = args.ipinfo_token

# function to resolve domain to IPv4
async def resolve_domain(domain, dns_server):
    dnsresolver = dns.resolver.Resolver()
    dnsresolver.nameservers = [dns_server]
    try:
        domain_obj = []
        domain_obj.append(domain)
        dnsresolver = list(dnsresolver.resolve(domain, 'A'))
        domain_obj.append(str(dnsresolver.pop()))
        return domain_obj
    except Exception as e:
        domain_obj = []
        domain_obj.append(domain)
        domain_obj.append("N/A")
        return domain_obj

# function to query shodan's internetdb for known ports and cves as well as ipinfo.io
async def query_shodan(domain_obj):

    ip = domain_obj[1]

    # if the domain previously resolved to an IPv4
    if ip != "N/A":
        try:
            # query InternetDB by shodan for CVE and port information
            apirequest = requests.get("https://internetdb.shodan.io/{0}".format(ip)).json()
            openPortsShodan = apirequest['ports']
            vulnsShodan = apirequest['vulns']

            # if the results are empty, replace with N/A string
            if len(openPortsShodan) == 0:
                openPortsShodan = "N/A"
            if len(vulnsShodan) == 0:
                vulnsShodan = "N/A"

        # catching error in case shodan's internetdb is unavailable
        except:
            openPortsShodan = "N/A"
            vulnsShodan = "N/A"
            
        try:
            # query ipinfo.com API for IP information
            ipinforequest = requests.get("https://ipinfo.io/{0}?token={1}".format(ip,apitoken)).json()
            ipinfo = ipinforequest
        except:
            ipinfo = "N/A"

        # if the results from ipinfo are empty
        if len(ipinfo) == 0 or ipinfo == "N/A":
            asn = "N/A"
            organization = "N/A"
            city = "N/A"
            region = "N/A"
            country = "N/A"
        # if the results are not empty, process it
        else:
            if ipinfo['org'].startswith('AS'):
                asn = ipinfo['org'].split(" ", 1)[0]
                organization = ipinfo['org'].split(" ", 1)[1]
                city = ipinfo['city']
                region = ipinfo['region']
                country = ipinfo['country']
            else:
                asn = "N/A"
                organization = ipinfo['org']
                city = ipinfo['city']
                region = ipinfo['region']
                country = ipinfo['country']

        # append results to list object
        domain_obj.append(openPortsShodan)
        domain_obj.append(vulnsShodan)
        domain_obj.append(asn)
        domain_obj.append(organization)
        domain_obj.append(city)
        domain_obj.append(region)
        domain_obj.append(country)

    # if the domain could not be resolved, insert N/A strings
    else:
        openPortsShodan = "N/A"
        vulnsShodan = "N/A"
        ipinfo = "N/A"
        asn = "N/A"
        organization = "N/A"
        city = "N/A"
        region = "N/A"
        country = "N/A"

        domain_obj.append(openPortsShodan)
        domain_obj.append(vulnsShodan)
        domain_obj.append(asn)
        domain_obj.append(organization)
        domain_obj.append(city)
        domain_obj.append(region)
        domain_obj.append(country)

async def main():

    domains = []

    # open file and read domains line by line
    with open(hostfile,'r') as fin:
        lines = fin.readlines()
    # store each domain in domain list
    for line in lines:
        domains.append(str(line).rstrip("\n"))

    # get unique hosts by converting to set and back
    domains = list(set(domains))

    tasks = []
    # resolve domains asynchonously
    print("[~] DNS resolving hostnames to IP")
    for i in range(len(domains)):
        tasks.append(asyncio.ensure_future(resolve_domain(domains[i], dns_server)))
    results = await asyncio.gather(*tasks)

    # retrieve port, cve and ip infos asynchonously
    print("[~] Querying shodan's internet db and ipinfo.io")
    for i in range(len(results)):
        tasks.append(asyncio.ensure_future(query_shodan(results[i])))
    results2 = await asyncio.gather(*tasks)

    # write the CSV
    with open(outfile, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Rootdomain', 'Domain', 'IP', 'Ports', 'CVEs', 'ASN', 'Organization', 'City', 'Region', 'Country'])

        try:
            for obj in results2:
                obj.insert(0, str(tldextract.extract(obj[0].strip()).registered_domain))
                writer.writerow(obj)
        except:
            pass

    print("[!] Output CSV " + str(outfile) + " successfully written.")

#loop = asyncio.get_event_loop()
#loop.run_until_complete(main())

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)
try:
    asyncio.run(main())
except KeyboardInterrupt:
    pass
