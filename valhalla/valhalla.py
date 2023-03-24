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
               Version: v0.1


"""

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group()

group.add_argument('-p', '--port', action='store',
                   help="port number to use",
                   metavar="8080")

parser.add_argument('-d', '--dork',
                   help="Dork to scan")

parser.add_argument('-f', '--file',
                   help="file to scan")

args = parser.parse_args()

print(banner)

SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)

if args.file:
 if args.port:
    with open(f'{args.file}', 'r') as f:
        domain_list = [x.strip() for x in f.readlines()]
        for domains in domain_list:
            fetch_requests.scan(domains,args.port)

if args.dork:
    if args.port:
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
                    fetch_requests.scan(iplist,args.port)                  
        except shodan.APIError as e:
            print(e)
    else:
        pass
    
