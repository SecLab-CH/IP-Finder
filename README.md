# :mag: IP-Finder :earth_americas:
IP-Finder is an Open Source Intelligence (OSINT) tool that helps you collect IPs of companies, Servers, OS and much more. 
This tool uses some of the best Search Engines (Shodan.io, ZoomEye.org and Censys.io)

# Supported OS:
```
Linux
Windows
Android
```
# Install:
```
$ git clone https://github.com/SecLab-CH/IP-Finder
$ pip3 install -r requirements.txt
```

# Setup:
```
[+] SHODAN & ZOOMEYE
Paste your <API_KEY> into code

[+] CENSYS
$ censys config
Paste your <Censys_API_ID> and <Censys_API_Secret>
```

# Run:
```
$ python3 IP-Finder.py --search (your search) Example: $ python3 IP-Finder.py --search "apache/2.4.1"
