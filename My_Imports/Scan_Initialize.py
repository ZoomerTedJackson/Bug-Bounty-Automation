from My_Imports.Discord_Webhook import scan_status_alert,send_error_alert
from Scans.General_Checks import *

# cycle through and run smuggler on each domain then check output worthy of alerting me
def initialize_smuggler(all_new_domains):
    print("Running Smuggler on New Domains...")
    for domain in all_new_domains:
        scan_status_alert(f"Running Smuggler on {domain}")
        try:
            run_smuggler_on_new_domains(domain)
        except Exception as e:
            send_error_alert(f"Main script failed during Smuggler checks.\nDomain:{domain}\n{e}")

# cycle through and run Nuclei on each domain then check output worthy of alerting me
def initialize_nuclei(all_new_domains,scanname):
    print("Running Nuclei on New Domains...")
    for domain in all_new_domains:
        scan_status_alert(f"Running Nuclei on {domain}")
        try:
            run_nuclei_on_new_domains(domain,scanname)
        except Exception as e:
            send_error_alert(f"Main script failed during Nuclei checks.\nDomain:{domain}\n{e}")

# cycle through and run wappalyzer on each domain then check versions against NIST CVE Database
def initialize_wappalyzer(all_new_domains):
    print("Looking for software versions and known CVEs on New Domains...")
    for domain in all_new_domains:
        scan_status_alert(f"Checking for software with known vulnerabilities on {domain}")
        run_wappalyzer_service_detection(domain)