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
												 										
                 https://www.sec-lab.com
	       
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
			if Search.lower() in result['data'].lower():
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

def searching():
	print(stylize("--------------------------------------------------------------------", colored.fg("white")))
	print(stylize(f"""[+] Search for: {options.search}\n""",colored.fg('cyan')))
	print(stylize(f"""[+] Searching in Shodan. . .\n""",colored.fg('yellow')))
	print(stylize(f"""[+] Searching in Censys. . .\n""",colored.fg('cyan')))
	print(stylize(f"""[+] Searching in Zoomeye. . .\n""",colored.fg('yellow')))
	print(stylize("--------------------------------------------------------------------", colored.fg("white")))


def switch(argument):
	print(stylize("--------------------------------------------------------------------", colored.fg("white")))
	print("[?] Which Search Engines do you want use? [?] ")
	print("[!] Please put '+' delimiter if you want to search on multiple Search Engines! [!] ")
	print("s --> Shodan, c --> Censys, z --> ZoomEye, a --> All ")
	choice = input('Enter your choice --> ')
	searching()
	output = []
	choicelow=choice.lower()
	if len(choicelow) == 1:
		engine = choicelow
	else:
		engine = choicelow.split("+")
	for opt in engine:
		if opt != 's' and opt != 'c' and opt != 'z' and opt != 'a':
			print("[-] Invalid Search Engine!")
			sys.exit(0)
	if len(engine) == 1 and engine == 'a':
		Shodan(argument, output)
		Censys(argument, output)
		ZoomEye(argument, output)
	else:
		for option in engine:
			if option == 's':
				Shodan(argument, output)
			elif option == 'c':
				Censys(argument, output)
			elif option == 'z':
				ZoomEye(argument, output)
			else:
				sys.exit(0)
	try:
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
		print(stylize("""[-] Please specify Search.
		Example: python3 IP-Finder.py Device type or version""", colored.fg('cyan')))
		
		
print(stylize(logo,colored.fg('cyan')))
(options, arguments) = Start()
if len(sys.argv) == 1:
		print(stylize("""[-] Please specify Search. Example: python3 IP-Finder.py Device type or version""", colored.fg('cyan')))
		sys.exit(0)
switch(options.search)
