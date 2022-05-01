# :mag: IP-Finder :earth_americas:
IP-Finder is an open source intelligence (OSINT) tool that helps collect IPs of Companies, Servers, Operating Systems and much more.
It also reports all CVEs (with the associated Metasploit module to run) for which different endpoints are affected.
This tool uses some of the best search engines (Shodan.io, ZoomEye.org and Censys.io).

# Requirements:
```
[*] Metasploit Framework
[*] Python version 3

[*] Successfully tested on Kali Linux OS
```

# Install:
```
$ git clone https://github.com/SecLab-CH/IP-Finder
$ pip3 install -r requirements.txt
```

# Setup:
```
[+] SHODAN & ZOOMEYE
Copy your <API_KEY> in config_api.py file

[+] CENSYS
$ censys config
Copy your <Censys_API_ID> and <Censys_API_Secret>
```

# Run:
```
$ python3 IP-Finder.py --search (your search) Example: $ python3 IP-Finder.py --search "apache 2.4.1"
