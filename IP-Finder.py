#Author:    Security Lab
#Github:    https://github.com/SecLab-CH
#Website:   https://www.sec-lab.com/

import requests,json,colored,time,shodan
from censys.search import CensysHosts
import zoomeye.sdk as zoomeye
from optparse import *
from colored import stylize
from bs4 import BeautifulSoup
import requests
import sys

logo = """
 
	 ___________  ______ _           _           
	|_   _| ___ \ |  ___(_)         | |          
	  | | | |_/ / | |_   _ _ __   __| | ___ _ __ 
	  | | |  __/  |  _| | | '_ \ / _` |/ _ \ '__|
	 _| |_| |     | |   | | | | | (_| |  __/ |   
	 \___/\_|     \_|   |_|_| |_|\__,_|\___|_|   
												 										
                                                                
"""

    
def Start():
	choose = OptionParser()
	choose.add_option("-s","--search",dest="search",help="Product or OS or Device, etc you want to search for")
	return choose.parse_args()


def Censys(Search, output):
	h = CensysHosts()
	results = h.search(Search, pages=-1)
	for result in results:
		if result[0]['ip'] is not output:
			output.append(result[0]['ip'])
			
def Shodan(Search, output):
	SHODAN_API_KEY = "YOUR_SHODAN_API_KEY"
	api = shodan.Shodan(SHODAN_API_KEY)
	try:
		results = api.search(Search)
		for result in results['matches']:
			success = False
			if all(x in result['data'] for x in Search):
				success = True
			if success != False:
				if result['ip_str'] is not output:
					output.append(result['ip_str'])
	except shodan.APIError as e:
		print('Error: {}'.format(e))

def ZoomEye(Search, output):
	zm = zoomeye.ZoomEye()
	zm.api_key = "YOUR_ZOOMEYE_API_KEY"
	results = zm.dork_search(Search)
	for result in results:
		if result['ip'] is not output:
			output.append(result['ip'])


print(stylize(logo,colored.fg('cyan')))


(options, arguments) = Start()

try:
	if len(sys.argv) == 1:
		print(stylize("""[-] Please specify Search. Example: python3 IP-Finder.py -s Device type or version""", colored.fg('cyan')))
		sys.exit(0)
	output = []
	str = ''
	print(stylize(f"""[+] Search for: {options.search}\n""",colored.fg('cyan')))
	print(stylize(f"""[+] Searching in Shodan. . .\n""",colored.fg('yellow')))
	print(stylize(f"""[+] Searching in Censys. . .\n""",colored.fg('cyan')))
	print(stylize(f"""[+] Searching in Zoomeye. . .\n""",colored.fg('yellow')))
	Censys(options.search, output)
	Shodan(options.search, output)
	ZoomEye(options.search, output)
	for host in output:
		print(stylize("--------------------------------------------------------------------", colored.fg("white")))
		print("[+] " + host)
		print(stylize("[+] CVEs", colored.fg("red")))
		url = "https://internetdb.shodan.io/" + host
		res = requests.get(url).json()
		if len(res.keys()) > 1:
			print(stylize(res [u'vulns'], colored.fg("red")))
	print(stylize("--------------------------------------------------------------------", colored.fg("white")))
	print(stylize("[+] Search Done", colored.fg("red")))
	
except Exception as e:
	print(e)
	print(stylize("""[-] Please specify Search
	ex: python3 IP-Finder.py -s Device type or version""", colored.fg('cyan')))

