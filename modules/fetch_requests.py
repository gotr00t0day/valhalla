from colorama import Fore
from modules import sub_output
import nuclei_parser

def scan(ip: str, port: str):
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning{Fore.GREEN} https://{ip}...\n")
        sub_output.scan(f"nuclei -u https://{ip} -t cves/ -severity medium,high,critical -c 100 -j -o vulnerable.json")
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning{Fore.GREEN} https://{ip}...\n")
        sub_output.scan(f"nuclei -u https://{ip} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ip}:{Fore.CYAN}{port}\n")
        sub_output.scan(f"nuclei -u http://{ip}:{port} -t cves/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        sub_output.scan(f"nuclei -u http://{ip}:{port} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()

def cve_scan(ips: str, port: str, cve: str): 
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} https://{ips}")
        sub_output.scan(f"nuclei -u https://{ips} -id {cve} -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ips}:{port}")
        sub_output.scan(f"nuclei -u http://{ips}:{port} -id {cve} -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()       


def cve_scan_file(file: str, cve: str):
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning for {Fore.GREEN}{cve}...\n")
    sub_output.scan(f"nuclei -id {cve} -l {file} -c 100 -silent -j -o vulnerable.json")
    nuclei_parser.parse()

def cve_scan_dork(ips: str, port: str, cve: str):      
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning{Fore.GREEN} https://{ips}...\n")
        sub_output.scan(f"nuclei -u https://{ips} -id {cve} -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ips}:{Fore.CYAN}{port}...\n")
        sub_output.scan(f"nuclei -u http://{ips}{port} -id {cve} -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()

def vuln_scan(ip: str, port: str):
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} https://{ip}")
        sub_output.scan(f"nuclei -u https://{ip} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()      
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} http://{ip}{port}")
        sub_output.scan(f"nuclei -u http://{ip}:{port} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse() 

def vuln_dork(ip: str, port: str, dork):
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} https://{ip}")
        sub_output.scan(f"nuclei -u https://{ip} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()      
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} http://{ip}{port}")
        sub_output.scan(f"nuclei -u http://{ip}:{port} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()    