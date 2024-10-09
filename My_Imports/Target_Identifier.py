import requests
import hashlib
import os
from config.Config import *
from My_Imports.Discord_Webhook import *

def get_latest_domains(domainurl, wildcardurl):
    domain_file_path = "/root/BB_Automation_Scope/New_Domains.txt"
    wildcard_file_path = "/root/BB_Automation_Scope/New_Wildcards.txt"
    with open(domain_file_path, 'wb') as out_file:
        content = requests.get(domainurl, stream=True).content
        out_file.write(content)
    with open(wildcard_file_path, 'wb') as out_file:
        content = requests.get(wildcardurl, stream=True).content
        out_file.write(content)

#Im adding new scope at the end so the hashes never match. I need a better way to compare the files or maybe I should just not bother...
def md5sum(filename):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(128 * md5.block_size), b''):
            md5.update(chunk)
    return md5.hexdigest()

def check_scope_change(scopetype):
    print(f"Checking if there have been any changes in bug bounty scope ({scopetype})...")
    scan_status_alert(f"Checking if there have been any changes in bug bounty scope ({scopetype})...")
    if scopetype == "domains":
        newdomainsbool = True
        if md5sum(New_Domains_Location) == md5sum(Known_Domains_Location):
            print("No new Domains")
            newdomainsbool = False
        return newdomainsbool
    elif scopetype == "wildcards":
        newwildcardsbool = True
        if md5sum(New_Wildcards_Location) == md5sum(Known_Wildcards_Location):
            print("No new Wildcards")
            newwildcardsbool = False
        return newwildcardsbool
    else:
        print("invalid scope type...skipping check")
        return False

def update_known_domains_file(known_domains, new_domains):
    try:
        with open(known_domains, 'a') as file:  # 'a' mode for appending
            for domain in new_domains:
                file.write(f"{domain}\n")
    except IOError:
        print("Error: could not update file " + known_domains)

def compare_domains_list(known_domains, new_domains):
    new_Domains_This_Check = []

    # Read known domains into a set for fast lookup
    with open(known_domains) as file:
        known_domains_set = set(line.strip() for line in file)

    # Read new domains and check for additions
    with open(new_domains) as file:
        for line in file:
            new_domain = line.strip()
            if new_domain not in known_domains_set:
                new_Domains_This_Check.append(new_domain)

    return new_Domains_This_Check