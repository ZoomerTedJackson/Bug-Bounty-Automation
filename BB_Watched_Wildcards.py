'''
This script is set to run every hour to check a random wildcard in Bug Bounty scope and
run a few tools and scans on them in order to alert me of anything worth looking at. This is a way to continually look
for new subdomains on existing wildcard scope.
'''
from pathlib import Path
from My_Imports.Target_Identifier import *
from My_Imports.Discord_Webhook import *
from Scans.General_Checks import *
from config.Config import *
from My_Imports.Scan_Initialize import *
from Scans.Intensive_Checks import *

#list of domains to be scanned
all_new_domains = []
#list of watched wildcard domains
watched_domains = []

def main():
    scan_status_alert("----------------------------------------")

    scan_status_alert("Starting Watched Wildcards Scanner")

    #check Watched_Domains.txt and import the domains into the list
    with open(Domains_to_watch, 'r') as file:
        for domain in file:
            watched_domains.append(domain)

    '''
    for each domain i am watching:
    run sublist3r
    check if the subdomain file for this domain exists.
    if not, create it and put curr_scan_domains list in it
    if so, check for new items and add only the new items in all_new_domains list
    '''
    for chosen_wildcard_domain in watched_domains:
        #initializing a list because i need sublist3r result as a list and sublist3r returns a set
        curr_scan_domains = []
        curr_scan_new_domains = []
        scan_status_alert(f"Running sublist3r on {chosen_wildcard_domain}")
        curr_scan_domains.extend(run_sublist3r_on_wildcards(chosen_wildcard_domain[2:]))
        #commenting out amass scan until i figure out why its breaking
        #scan_status_alert(f"Running Amass on {chosen_wildcard_domain}")
        #curr_scan_domains.extend(run_amass_subdomain_finder(chosen_wildcard_domain[2:]))
        chosen_wildcard_domain = chosen_wildcard_domain.rstrip()
        subdomainfile = Path(f"{Watched_Domain_Subdomains_Dir}{chosen_wildcard_domain[2:]}.txt")
        if subdomainfile.is_file(): # if file exists, check for new subdomains from the latest scan
            curr_scan_new_domains = []
            try:
                with open(subdomainfile, 'r') as file:
                    existing_domains = set(line.strip().lower() for line in file)

                for domain in curr_scan_domains:
                    if domain.lower() not in existing_domains:
                        curr_scan_new_domains.append(domain)
                        all_new_domains.append(domain)
            except Exception as e:
                send_error_alert(f"Watched domains script failed while checking for new subdomains.\n{e}")

            if curr_scan_new_domains:
                watched_domain_new_sub_alert(curr_scan_new_domains,chosen_wildcard_domain)
        else: #if the file doesn't exist, alert me that a new watched domain has been initialized
            all_new_domains.extend(curr_scan_domains)
            curr_scan_new_domains.extend(curr_scan_domains)
            initialize_watched_domains_alert(curr_scan_domains,chosen_wildcard_domain)

        try:
            if curr_scan_new_domains: #if there are new domains, update the existing file
                with open(subdomainfile, 'a') as file:  # 'a' mode for appending
                    for domain in curr_scan_new_domains:
                        file.write(f"{domain}\n")
        except Exception as e:
            send_error_alert(f"Watched domains script failed while updating the watched subdomain file for {chosen_wildcard_domain}.\n{e}")

    '''
    tools and scans to be ran on the domains gathered from the wildcard
    '''
    if all_new_domains:
        scan_status_alert(f"Starting scans on new domains.\nNumber of new domains: {len(all_new_domains)}")
        # cycle through and run smuggler on each domain then check output worthy of alerting me
        initialize_smuggler(all_new_domains)

        # cycle through and run Nuclei on each domain then check output worthy of alerting me
        initialize_nuclei(all_new_domains,"Watched")

        # cycle through and run wappalyzer on each domain then check versions against NIST CVE Database
        initialize_wappalyzer(all_new_domains)

    scan_status_alert("Watched Wildcards Scanner Completed Successfully")

if __name__ == "__main__":
    main()
