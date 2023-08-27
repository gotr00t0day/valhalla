from colorama import Fore
from modules import sub_output, nmap_parse
import nuclei_parser


def scan(ip: str, port: str):
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning{Fore.GREEN} https://{ip}...\n")
        sub_output.scan(f"nuclei -u https://{ip} -t cves/ -severity medium,high,critical -c 100 -j -o vulnerable.json")
        nuclei_parser.parse()
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ip}:{Fore.CYAN}{port}\n")
        sub_output.scan(f"nuclei -u http://{ip}:{port} -t cves/ -severity medium,high,critical -c 100 -silent -j -o vulnerable.json")
        nuclei_parser.parse()

def cve_scan(ips: str, port: str, cve: str):
    if port == "443":
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} https://{ips} {Fore.CYAN} {cve}")
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

def nmap_scan(ips: str):
    sub_output.scan(f"nmap -sV -p80,81,8080,8081 -T4 {ips} -oX nmap_results.xml")
    results = nuclei_parser.parse()
    if results is None:
        pass
    elif "80" in results:
        print(f"{Fore.MAGENTA}[+] {Fore.WHITE}[{Fore.CYAN}{ips}{Fore.WHITE}][{Fore.YELLOW}80{Fore.WHITE}][http]{Fore.RESET}")
    elif "81" in results:
        print(f"{Fore.MAGENTA}[+] {Fore.WHITE}[{Fore.CYAN}{ips}{Fore.WHITE}][{Fore.YELLOW}81{Fore.WHITE}][http]{Fore.RESET}")
    elif "443" in results:
        print(f"{Fore.MAGENTA}[+] {Fore.WHITE}[{Fore.CYAN}{ips}{Fore.WHITE}][{Fore.YELLOW}443{Fore.WHITE}][https]{Fore.RESET}")

def file_scan(file: str):
    print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scanning {Fore.GREEN}{file} for vulnerabilities...\n")
    sub_output.scan(f"nuclei -l {file} -t vulnerabilities/ -severity medium,high,critical -c 100 -silent")
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
