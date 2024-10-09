from Wappalyzer import Wappalyzer, WebPage
from Scans.Intensive_Checks import *

domains = ['*.dev.remitly.com']
for host in domains:
    print(run_amass_subdomain_finder(host[2:]))