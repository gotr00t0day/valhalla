from modules import fetch_requests, shodan_con
from colorama import Fore
import argparse
import shodan



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
               Version: v1.6


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

parser.add_argument('-vuln', '--vulnerability', action='store_true',
                   help="scan for vulnerabilities")

parser.add_argument('-ips', '--ipaddresses', action='store_true',
                   help="getting ip addresses from shodan")

args = parser.parse_args()

print(banner)

if args.dork:
    if args.ipaddresses:
        print(f"Extracting IP Adddresses from {Fore.CYAN}Shodan{Fore.RESET}...")
        shodan_con.ips(args.dork)
        print(f"DONE{Fore.MAGENTA}!\n")

if args.target:
    if args.port:
        if args.cve_id:
            fetch_requests.cve_scan(args.target, args.port, args.cve_id)

if args.target:
    if args.port:
        fetch_requests.scan(args.target, args.port)

if args.file:
    if args.cve_id:
        with open(f'{args.file}', 'r') as f:
            domain_list = [x.strip() for x in f.readlines()]
            for domains in domain_list:
                fetch_requests.cve_scan_file(args.file, args.cve_id) 

if args.file:
 if args.port:
    with open(f'{args.file}', 'r') as f:
        domain_list = [x.strip() for x in f.readlines()]
        for domains in domain_list:
            fetch_requests.scan(domains, args.port)

if args.dork:
    if args.port:
        if args.cve_id:
            try:
                shodan_con.ips(args.dork)
                with open('ips.txt', 'r') as f2:
                    ip_list = [x.strip() for x in f2.readlines()]
                    for iplist in ip_list:
                        fetch_requests.cve_scan_dork(iplist, args.port, args.cve_id)                  
            except shodan.APIError as e:
                print(e)
        else:
            pass

if args.dork:
    if args.port:
        try:
            shodan_con.ips(args.dork)
            with open('ips.txt', 'r') as f2:
                ip_list = [x.strip() for x in f2.readlines()]
                for iplist in ip_list:
                    fetch_requests.scan(iplist, args.port)                  
        except shodan.APIError as e:
            print(e)
    else:
        pass

if args.target:
    if args.vulnerability:
        if args.port:
            fetch_requests.vuln_scan(args.target, args.port)

if args.dork:
    if args.port:
        if args.vulnerability:
            try:
                shodan_con.ips(args.dork)
                with open('ips.txt', 'r') as f2:
                    ip_list = [x.strip() for x in f2.readlines()]
                    for iplist in ip_list:
                        fetch_requests.vuln_dork(iplist, args.port, args.vulnerability)                  
            except shodan.APIError as e:
                print(e)
        else:
            pass