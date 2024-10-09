'''
This script is set to run every few hours to check for new Bug Bounty scope and
run a few tools and scans on them in order to alert me of anything worth looking at.
'''
from My_Imports.Target_Identifier import *
from My_Imports.Discord_Webhook import *
from Scans.General_Checks import *
from config.Config import *
from My_Imports.Scan_Initialize import *

#list of new domains to be added to via all sources as script grows
all_new_domains = []

def main():
    scan_status_alert("----------------------------------------")
    scan_status_alert("Starting New Scope Scanner")
    # Fetch the latest domains
    print("Getting a list of in-scope domains...")
    scan_status_alert("Getting a list of in-scope domains...")
    get_latest_domains(in_Scope_Domains_URL,in_Scope_Wildcards_URL)
    print("Success!\n\n")

    # Compare the MD5 checksums of the known and new domains to see if there were any changes
    newdomainsbool = check_scope_change("domains")
    newwildcardsbool = check_scope_change("wildcards")

    #initializing these early for alerting purposes
    new_wildcard_domains = []
    new_domains = []

    #enumerate new domains and add to list of domains to scan
    if newdomainsbool:
        print("Domain files appear to be different!")
        print("Looking for new domains...")
        # Check which domains have been added to the list
        try:
            new_domains = compare_domains_list(Known_Domains_Location, New_Domains_Location)
            all_new_domains.extend(new_domains)
        except Exception as e:
            send_error_alert(f"Main script failed while finding new domains.\n{e}")

    #enumerate new wildcard scope and send each wildcard to sublist3r in order to add subdomains to the list of domains to scan
    if newwildcardsbool:
        print("Wildcard files appear to be different!")
        print("Looking for new wildcard domains...")
        try:
            new_wildcard_domains = compare_domains_list(Known_Wildcards_Location, New_Wildcards_Location)
        except Exception as e:
            send_error_alert(f"Main script failed while finding new wildcard domains.\n{e}")

        if new_wildcard_domains:
            for domain in new_wildcard_domains:
                try:
                    if domain[:2] == "*.":
                        scan_status_alert(f"Running Sublist3r on {domain}")
                        all_new_domains.extend(run_sublist3r_on_wildcards(domain[2:]))
                except:
                    send_error_alert("Main script failed while running sublist3r on wildcards")
        else:
            print("No new wildcard domains found.\n")

    # send the new domains to my Discord alert channel
    if all_new_domains or new_wildcard_domains:
        print("\nNew domains found!\nSending alert to Discord\n")
        scan_status_alert("New domains found!\nSending alert to Discord")
        new_scope_alert(new_domains, new_wildcard_domains)
    else:
        print("No new domains found.\n")

    '''
    operations to be ran after compiling a total list of domains from processing direct domain list
    and finding domains from the wildcards
    '''
    if all_new_domains:
        scan_status_alert(f"Starting scans on new domains.\nNumber of new domains: {len(all_new_domains)}")

        # cycle through and run smuggler on each domain then check output worthy of alerting me
        initialize_smuggler(all_new_domains)

        # cycle through and run Nuclei on each domain then check output worthy of alerting me
        initialize_nuclei(all_new_domains,"New_Scope")

        # cycle through and run wappalyzer on each domain then check versions against NIST CVE Database
        initialize_wappalyzer(all_new_domains)


    #add new domains to the Known_Domains file in preparation for the next check
    try:
        scan_status_alert("Updating known domains files")
        update_known_domains_file(Known_Domains_Location, new_domains)
        update_known_domains_file(Known_Wildcards_Location, new_wildcard_domains)
    except Exception as e:
        send_error_alert(f"Main script failed while updating known domains/wildcards files.\n{e}")

    scan_status_alert("New Scope Scanner Completed Successfully")

if __name__ == "__main__":
    main()
