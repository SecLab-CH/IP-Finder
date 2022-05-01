# :mag: IP-Finder :earth_americas:
IP-Finder is an Open Source Intelligence (OSINT) tool that helps you collect IPs of Companies, Servers, OS and much more.
It also reports all the CVEs for which the different Endpoints are affected.
This tool uses some of the best Search Engines (Shodan.io, ZoomEye.org and Censys.io)


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
