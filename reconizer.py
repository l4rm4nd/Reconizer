import asyncio
import aiohttp
import aiodns
import tldextract
import csv
import argparse
from tqdm.asyncio import tqdm  # Import tqdm for the progress bar
import json

dns_server = '1.1.1.1'

parser = argparse.ArgumentParser("prscan.py")
parser.add_argument("--hostfile", metavar='<file>', help="A txt file with hosts per newline", type=str, required=True)
parser.add_argument("--ipinfo-token", metavar='<token>', help="API token for ipinfo.com", type=str, required=True)
parser.add_argument("--output", metavar='<output>', help="Output CSV filename", type=str, default="reconizer-results.csv")  # Add a default filename

args = parser.parse_args()
hostfile = args.hostfile
apitoken = args.ipinfo_token
output_filename = args.output  # Get the specified output filename from the command line argument

async def resolve_dns(domain, resolver):
    try:
        result = await resolver.query(domain, 'A')
        return result[0].host
    except Exception:
        return ""

async def fetch_shodan_data(session, ip):
    try:
        async with session.get(f"https://internetdb.shodan.io/{ip}") as response:
            return await response.json()
    except Exception:
        return {"ports": [], "vulns": []}

async def fetch_ipinfo_data(session, ip, token):
    try:
        async with session.get(f"https://ipinfo.io/{ip}?token={token}") as response:
            return await response.json()
    except Exception:
        return {}

async def process_domain(domain, resolver, session, token, existing_requests):
    ip = await resolve_dns(domain, resolver)
    if ip in existing_requests:
        return existing_requests[ip]

    if ip:
        shodan_data = await fetch_shodan_data(session, ip)
        ipinfo_data = await fetch_ipinfo_data(session, ip, token)
    else:
        shodan_data = {"ports": [], "vulns": []}
        ipinfo_data = {}

    result = (ip, shodan_data.get('ports', []), shodan_data.get('vulns', []), ipinfo_data)
    existing_requests[ip] = result
    return result

async def prscan(hostfile, token, output_filename):
    domains = []
    with open(hostfile, 'r') as fin:
        lines = fin.readlines()
    for line in lines:
        domains.append(str(line).rstrip("\n"))
    domains = list(set(domains))

    resolver = aiodns.DNSResolver(nameservers=[dns_server])
    async with aiohttp.ClientSession() as session:
        existing_requests = {}
        tasks = [process_domain(domain, resolver, session, token, existing_requests) for domain in domains]

        results = await tqdm.gather(*tasks)  # Use tqdm for the progress bar

    crtscan = {
        "domains": domains,
        "ips": [res[0] for res in results],
        "openPortsShodan": [res[1] for res in results],
        "vulnsShodan": [res[2] for res in results],
        "ipinfo": [res[3] for res in results],
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
            ports = str(ports)[1:-1].replace(' ', '')
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
            cves = str(cves)[1:-1].replace(' ', '')

        print(f'HOST-{i};{tldextract.extract(domain.strip()).registered_domain};{domain};{ip};{ports};{cves};{asn};{organization};{city};{region};{country}')

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
                ports = str(ports)[1:-1].replace(' ', '')
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
                cves = str(cves)[1:-1].replace(' ', '')

            csv_writer.writerow([f'HOST-{i}', tldextract.extract(domain.strip()).registered_domain, domain, ip, ports, cves, asn, organization, city, region, country])

if __name__ == '__main__':
    asyncio.run(prscan(hostfile, apitoken, output_filename))
