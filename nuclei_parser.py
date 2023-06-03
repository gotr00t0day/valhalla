from colorama import Fore
from modules import sub_output
import json
import os

##  Nuclei Parser By c0d3Ninja
##  Version: 1.1

def parse():
    dirpath = os.path.abspath(os.getcwd())
    if not os.path.isfile(f"{dirpath}/vulnerable.json"):       
        with open("vulnerable.json", "w") as f:
            f.writelines()
    else:
        with open("vulnerable.json", "r") as f:
            data = [x.strip() for x in f.readlines()]
        read_data = []
        results = []
        for data_list in data:
            read_data.append(data_list)
        more_data = json.loads(json.dumps([read_data]))
        for datas in more_data:
            for data0 in datas:
                json_result = json.loads(data0)
                for k, v in json_result.items():
                    if "template-id" in k:
                        results.append(f"CVE: {k}")
                        print(f"{Fore.MAGENTA}CVE: {Fore.GREEN}{v}")
                    if "matched-at" in k:
                        results.append(f"PoC: {k}")
                        print(f"{Fore.MAGENTA}PoC: {Fore.GREEN}{v}\n")
                    if "info" in k:
                        for k2, v2 in v.items():
                            if "name" in k2:
                                new_v2 = v2.split(" ")[0]
                                results.append(f"Vulnerability: {v2}")
                                print(f"{Fore.MAGENTA}Vulnerability: {Fore.GREEN}{v2}")
        with open("results.txt", "w") as f:
            f.writelines(f"{results}\n")