from colorama import Fore
from modules import sub_output
import nuclei_parser
import requests
import random
import urllib3

_useragent_list = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2919.83 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2866.71 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2820.59 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2762.73 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2656.18 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"]



header = {"User-Agent": random.choice(_useragent_list)}
def scan(ips: str, port: int):
    if port == 443:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ips}:{Fore.CYAN}{port}\n")
        sub_output.scan(f"nuclei -u https://{ips} -t cves/ -severity medium,high,critical -c 100 -silent -json -o vulnerable.json")
        nuclei_parser.parse()
    else:
        print(f"{Fore.MAGENTA}[+] {Fore.CYAN}-{Fore.WHITE} Scannning{Fore.GREEN} {ips}:{Fore.CYAN}{port}\n")
        sub_output.scan(f"nuclei -u http://{ips}:{port} -t cves/ -severity medium,high,critical -c 100 -silent -json -o vulnerable.json")
        nuclei_parser.parse()