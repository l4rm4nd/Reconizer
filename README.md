# Reconizer
Python3 script to resolve hostnames to IP addresses and query Shodan's free InternetDB for ports and CVEs. Furthermore, ipinfo.com is queried for detailed IP information such as ASN, organization (hoster), city, region and country.

## Installation
````
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
````

## How to run

````
usage: reconizer.py [-h] --hostfile <file> --ipinfo-token <token>

optional arguments:
  -h, --help              show this help message and exit
  --hostfile <file>       A txt file with hosts per newline
  --ipinfo-token <token>  API token for ipinfo.com
````

## Example run
````
python3 reconizer.py --hostfile /home/Desktop/hosts.txt --ipinfo-token <API-TOKEN>
````

## Example results
````
[~] DNS resolving hostnames to IP
.
[~] Analyzing ports, CVEs and IP information
.
ID;DOMAIN;IP;PORTS;CVE;ASN;ORG;CITY;REGION;COUNTRY
HOST-0;google.com;142.250.185.78;80,443;N/A;AS15169;Google LLC;Frankfurt am Main;Hessen;DE
````
