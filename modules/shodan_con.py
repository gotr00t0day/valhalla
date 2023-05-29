import shodan

SHODAN_API_KEY = ""
api = shodan.Shodan(SHODAN_API_KEY)


def ips(dork: str):
    results = api.search(str(dork))
    ips = []
    for result in results['matches']:
        ips.append(result['ip_str'])
    with open("ips.txt", "w") as f:
           for ipaddresses in ips:
               f.writelines(f"{ipaddresses}\n")