'''
This Python3 script will query Shodan's InternetDB API to obtain additional hostnames.
It takes an input file with IP addresses, typically obtained after running the reconizer.py script.

Helps to identify additional hosts for the target domain(s) already enumerated
'''

import requests
import argparse
import re

def is_valid_ipv4(ip):
    # Regular expression to validate an IPv4 address
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(ip):
        # Further check to ensure each segment is between 0 and 255
        segments = ip.split('.')
        return all(0 <= int(segment) <= 255 for segment in segments)
    return False

def get_unique_hostnames(ip_addresses):
    hostnames = set()
    
    for ip in ip_addresses:
        url = f"https://internetdb.shodan.io/{ip.strip()}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            data = response.json()
            if 'hostnames' in data:
                hostnames.update(data['hostnames'])
        except requests.HTTPError as e:
            if 400 <= e.response.status_code < 500:
                # Ignore client errors (400-499)
                continue
            else:
                print(f"Error querying {ip}: {e}")
        except requests.RequestException as e:
            print(f"Error querying {ip}: {e}")
    
    return hostnames

def read_ip_addresses(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    unique_ips = set(ip.strip() for ip in lines if is_valid_ipv4(ip.strip()))
    return unique_ips

def main(input_file):
    ip_addresses = read_ip_addresses(input_file)
    unique_hostnames = get_unique_hostnames(ip_addresses)
    
    for hostname in sorted(unique_hostnames):
        print(hostname)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Query Shodan InternetDB for hostnames of given IP addresses.')
    parser.add_argument('input_file', type=str, help='Input file with IP addresses, one per line')
    args = parser.parse_args()
    
    main(args.input_file)
