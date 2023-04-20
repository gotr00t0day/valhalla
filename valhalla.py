from modules import sub_output, fetch_requests
from colorama import Fore
import argparse
import shodan
import requests
import urllib3

banner = f"""

            ,
       ,   |\ ,__
       |\   \/   `.
       \ `-.:.     `\\
        `-.__ `\=====|
           /=`'/   ^_\\
         .'   /\   .=)
      .-'  .'|  '-(/_|
    .'  __(  \  .'`
   /_.'`  `.  |`
            \ |
             |/  {Fore.RED}"No system is safe"{Fore.RESET}

____   ____      .__  .__           .__  .__          
\   \ /   /____  |  | |  |__ _____  |  | |  | _____   
 \   Y   /\__  \ |  | |  |  \\\\__  \ |  | |  | \__  \  
  \     /  / __ \|  |_|   Y  \/ __ \|  |_|  |__/ __ \_
   \___/  (____  /____/___|  (____  /____/____(____  /
               \/          \/     \/               \/ 
               Author:  c0deninja
               Version: v1.3


"""

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-p', '--port', action='store',
                   help="port number to use",
                   metavar="8080")

parser.add_argument('-t', '--target',
                   help="file to scan")

parser.add_argument('-d', '--dork',
                   help="Dork to scan")

parser.add_argument('-f', '--file',
                   help="file to scan")

parser.add_argument('-cve', '--cve_id',
                   help="scan by cve id")

parser.add_argument('-vuln', '--vulnerability',
                   help="scan for vulnerabilities")

args = parser.parse_args()

print(banner)

SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)

if args.target:
    if args.port:
        if args.cve_id:
            fetch_requests.cve_scan(args.target, args.port, args.cve_id)

if args.target:
    if args.port:
        fetch_requests.scan(args.target,args.port)

if args.file:
    if args.cve_id:
        with open(f'{args.file}', 'r') as f:
            domain_list = [x.strip() for x in f.readlines()]
            for domains in domain_list:
                fetch_requests.cve_scan_file(args.file,args.cve_id) 

if args.file:
 if args.port:
    with open(f'{args.file}', 'r') as f:
        domain_list = [x.strip() for x in f.readlines()]
        for domains in domain_list:
            fetch_requests.scan(domains,args.port)

if args.dork:
    if args.port:
        if args.cve_id:
            try:
                results = api.search(str(args.dork))
                ips = []
                for result in results['matches']:
                    ips.append(result['ip_str'])
                with open("ips.txt", "w") as f:
                    for ipaddresses in ips:
                        f.writelines(f"{ipaddresses}\n")
                with open('ips.txt', 'r') as f2:
                    ip_list = [x.strip() for x in f2.readlines()]
                    for iplist in ip_list:
                        fetch_requests.cve_scan_dork(iplist,args.port,args.cve_id)                  
            except shodan.APIError as e:
                print(e)
        else:
            pass
    
