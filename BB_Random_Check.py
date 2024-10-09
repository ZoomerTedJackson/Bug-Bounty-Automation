'''
This script is set to run every hour to check a random wildcard in Bug Bounty scope and
run a few tools and scans on them in order to alert me of anything worth looking at. This is a way to continually look
for new subdomains on existing wildcard scope.
'''

import random
from My_Imports.Target_Identifier import *
from My_Imports.Discord_Webhook import *
from Scans.General_Checks import *
from config.Config import *
from My_Imports.Scan_Initialize import *

#list of new domains to be added to via sublist3r
all_new_domains = []

def main():
    scan_status_alert("----------------------------------------")
    scan_status_alert("Starting Random Wildcard Scanner")
    #grab a random line from the known wildcard scope and run sublist3r on it
    try:
        chosen_wildcard_domain = random.choice(open(Known_Wildcards_Location).read().splitlines())
        scan_status_alert(f"Running Sublist3r on {chosen_wildcard_domain}")
        all_new_domains.extend(run_sublist3r_on_wildcards(chosen_wildcard_domain[2:]))
    except Exception as e:
        send_error_alert(f"Random domain script failed while looking for a random domain.\n{e}")

    '''
    tools and scans to be ran on the domains gathered from the wildcard
    '''
    if all_new_domains:
        scan_status_alert(f"Starting scans on domains.\nNumber of domains: {len(all_new_domains)}")
        # cycle through and run smuggler on each domain then check output worthy of alerting me
        initialize_smuggler(all_new_domains)

        # cycle through and run Nuclei on each domain then check output worthy of alerting me
        initialize_nuclei(all_new_domains,"Random")

        # cycle through and run wappalyzer on each domain then check versions against NIST CVE Database
        initialize_wappalyzer(all_new_domains)

    scan_status_alert("Random Wildcard Scanner Completed Successfully")

if __name__ == "__main__":
    main()
