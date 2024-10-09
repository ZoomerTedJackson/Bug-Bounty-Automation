import requests
import subprocess
import os
import re
from config.Config import *
from My_Imports.Extra_Methods import *


def run_amass_subdomain_finder(domain):
    subdomains = []
    command = f"/root/go/bin/amass enum -passive -d {domain} -norecursive -o /root/SecTools/amass_scan_output/currscanresults.txt"
    # Run the command and wait for it to complete
    subprocess.run(command, shell=True, check=True)

    try:
        f = os.path.join("/root/SecTools/amass_scan_output/", "currscanresults.txt")
        print(f)
        # checking if it is a file
        if os.path.isfile(f):
            with open(f, 'r') as file:
                for line in file:
                    # list out any relevant findings
                    if "(FQDN)" in line:
                        input_string = line

                        # Step 1: Extract the portion before "(FQDN)"
                        extracted_string = re.split(r'\s*\(FQDN\)\s*', input_string)[0]

                        # Step 2: Remove extra spaces and ANSI codes
                        extracted_string = extracted_string.strip()
                        extracted_string = escape_ansi(extracted_string)

                        subdomains.append(extracted_string)
                        # Step 3: Check if the extracted string ends with the value of 'domain'
                        if domain in extracted_string:
                            subdomains.append(extracted_string)
            #empty out the results file for next scan
            open(f, "w").close()
    except Exception as e:
        print(f"error with checking Amass output file.\n{e}")
    return list(subdomains)

