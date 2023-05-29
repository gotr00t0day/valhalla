# valhalla
Valhalla finds vulnerable devices on shodan, it can also scan a list of domains to find vulnerabilities.

# INSTALLATION

git clone https://github.com/gotr00t0day/valhalla.git

cd valhalla

pip3 install -r requirements.txt

# USAGE

```
            ,
       ,   |\ ,__
       |\   \/   `.
       \ `-.:.     `\
        `-.__ `\=====|
           /=`'/   ^_\
         .'   /\   .=)
      .-'  .'|  '-(/_|
    .'  __(  \  .'`
   /_.'`  `.  |`
            \ |
             |/  "No system is safe"

____   ____      .__  .__           .__  .__          
\   \ /   /____  |  | |  |__ _____  |  | |  | _____   
 \   Y   /\__  \ |  | |  |  \\__  \ |  | |  | \__  \  
  \     /  / __ \|  |_|   Y  \/ __ \|  |_|  |__/ __ \_
   \___/  (____  /____/___|  (____  /____/____(____  /
               \/          \/     \/               \/ 
               Author:  c0deninja
               Version: v1.6


usage: valhalla.py [-h] [-p 8080] [-t TARGET] [-d DORK] [-f FILE] [-cve CVE_ID]
                   [-vuln VULNERABILITY]

options:
  -h, --help            show this help message and exit
  -p 8080, --port 8080  port number to use
  -t TARGET, --target TARGET
                        file to scan
  -d DORK, --dork DORK  Dork to scan
  -f FILE, --file FILE  file to scan
  -cve CVE_ID, --cve_id CVE_ID
                        scan by cve id
  -vuln VULNERABILITY, --vulnerability VULNERABILITY
                        scan for vulnerabilities 
 ```

 # EXAMPLE

Normal Scan
```
python3 valhalla.py -t IP --port 443
```
Dork Scan
```
python3 valhalla.py -d 'SHODAN DORK HERE' --port 80
```
Scan a file with a CVE ID
```
python3 valhalla.py -f ips.txt --cve_id CVE-2022-30525
```
Scan a target with a CVE ID
```
python3 valhalla.py -t IP --port 443 --cve_id CVE-2022-30525
```
Dork Scan with a CVE ID
```
python3 valhalla.py -d 'DORK HERE' --cve_id CVE-2022-30525 --port 80
```
Vulnerability Scan
```
python3 valhalla.py -t IP --port 443 --vulnerability
```
Vulnerability Scan with a dork
```
python3 valhalla.py -d 'DORK HERE' --port 443 --vulnerability
```