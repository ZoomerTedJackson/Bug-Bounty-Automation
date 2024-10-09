import subprocess
from pathlib import Path
import sublist3r
import os
from Wappalyzer import Wappalyzer, WebPage
from My_Imports.Discord_Webhook import *
from My_Imports.Extra_Methods import *
from config.Config import *

def run_smuggler_on_new_domains(domain):
    """
    Run smuggler on the domain once with each HTTP Method.
    """
    http_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE"]
    try:
        for currHTTPMethod in http_methods:
            print(f"Running Smuggler on {domain} with HTTP Method {currHTTPMethod}...")
            # Replace 'your_tool_command' with the command for your tool
            result = subprocess.run(['python3', '/root/SecTools/smuggler/smuggler.py', '-u', domain, '-m', currHTTPMethod], check=True,
                                    capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while processing {domain}: {e.stderr}")

    print("Checking if Smuggler found anything...")
    if any(Path(smuggler_output_directory).iterdir()):
        print("Smuggler got a hit!\nSending alert to Discord")
        scan_status_alert("Smuggler got a hit!\nSending alert to Discord")
        smuggler_alert(smuggler_output_directory)
    else:
        print("Smuggler didn't find anything\n")

def run_nuclei_on_new_domains(domain, scanname):
    command = f"nuclei -u https://{domain} -it TedCustom -mhe 100  -o /root/SecTools/nuclei/scanoutput/currscanresults_{scanname}.txt"
    # Run the command and wait for it to complete
    subprocess.run(command, shell=True, check=True)
    info_findings = []
    low_findings = []
    medium_findings = []
    high_findings = []
    critical_findings = []
    try:
        f = os.path.join(nuclei_output_directory, f"{nuclei_output_file_prefix}_{scanname}.txt")
        # checking if it is a file
        if os.path.isfile(f):
            with open(f, 'r') as file:
                for line in file:
                    # list out any relevant findings
                    if "[info]" in line:
                        info_findings.append(line)
                    elif "[low]" in line:
                        low_findings.append(line)
                    elif "[medium]" in line:
                        medium_findings.append(line)
                    elif "[high]" in line:
                        high_findings.append(line)
                    elif "[critical]" in line:
                        critical_findings.append(line)

            # send alerts if anything was found
            if info_findings:
                print("\nFound Informationals")
                nuclei_alert("info", info_findings, domain)
            if low_findings:
                print("\nFound low Findings")
                scan_status_alert("Nuclei Found Low Finding(s)!\nSending alert to Discord")
                nuclei_alert("low", low_findings, domain)
            if medium_findings:
                print("\nFound Medium Findings")
                scan_status_alert("Nuclei Found Medium Finding(s)!\nSending alert to Discord")
                nuclei_alert("medium", medium_findings, domain)
            if high_findings:
                print("\nFound High Findings")
                scan_status_alert("Nuclei Found High Finding(s)!\nSending alert to Discord")
                nuclei_alert("high", high_findings, domain)
            if critical_findings:
                print("\nFound Critical Findings")
                scan_status_alert("Nuclei Found Critical Finding(s)!\nSending alert to Discord")
                nuclei_alert("critical", critical_findings, domain)
        open(f, "w").close()
    except Exception as e:
        print(f"error with checking Nuclei files.\n{e}")

def run_sublist3r_on_wildcards(domain):
    subdomains = sublist3r.main(domain, 40, '', ports= None, silent=False, verbose= False, enable_bruteforce= False, engines=None)
    return list(subdomains)

def run_wappalyzer_service_detection(domain):
    #Damn it wappalyzer, throwing an error on initialization smh
    wappalyzer = Wappalyzer.latest()
    try:
        webpage = WebPage.new_from_url(f'http://{domain}')
        data = wappalyzer.analyze_with_versions_and_categories(webpage)
    except:
        data = []
    print("\n" + domain + ":")
    for i in data:
        all_vulnerabilities = {}
        single_domain_vulnerabilities = []
        if data[i]["versions"]:
            print(f"{i} {data[i]["versions"][0]}")

            #find CPE by software name and version, then use that to pull CVEs associated into a dictionary
            cpe = find_cpes(f"{i} {data[i]["versions"][0]}")
            if cpe:
                single_domain_vulnerabilities = find_vulnerabilities_by_cpe(cpe)
            if single_domain_vulnerabilities:
                all_vulnerabilities[f"{i} {data[i]["versions"][0]}"] = single_domain_vulnerabilities

        '''
        because of discords character limit, send a separate alert for each software with known vulns.
        Lumping all the data for each domain risks cutting off entire specific software if theres too much data.
        
        Note to self: This is a bit ugly right now if a domain has multiple vulns, work on this.
        '''
        if all_vulnerabilities:
            scan_status_alert("Software with known vulnerabilities found!\nSending alert to Discord")
            version_number_alert(domain, all_vulnerabilities)

