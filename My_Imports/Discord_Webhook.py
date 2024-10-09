from tarfile import version

import requests
import os

error_discord_webhook_url = "https://discord.com/api/webhooks/{{{REPLACE}}}"

def send_alert(url, content):
    result = requests.post(url, json=content)

    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
        content["content"] = content["content"][0:1000]
        send_error_alert(f"Discord webhook failed. Posting partial alert here\n{content}")
    else:
        print(f"Sent Alert to Discord.\n\n")

def new_scope_alert(domains, wildcards):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content" : "---------------------------\nNew domains added to bug bounty scope since the last check:\n"
    }
    try:
        if domains:
            for single_domain in domains:
                data["content"] = data["content"] + single_domain + "\n"
        if wildcards:
            for single_wildcard in wildcards:
                data["content"] = data["content"] + single_wildcard + "\n"

        data["content"] = data["content"] + "\n" + "Running Scans on these domains..."
        # many results are too big for discord's 2000 character limit. Cut it off before then manually.
        data["content"] = data["content"][0:1800]
        send_alert(url, data)
    except:
        print("error with sending new domains alert")
        data["content"] = "There was an error sending updated in-scope domains to Discord."
        send_alert(error_discord_webhook_url, data)

def smuggler_alert(smuggler_output_directory):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content" : "---------------------------\nSmuggler has detected vulnerable hosts:\n"
    }
    #send intro message for alert
    send_alert(url, data)

    #send individual files:
    # iterate over files in directory
    try:
        for filename in os.listdir(smuggler_output_directory):
            f = os.path.join(smuggler_output_directory, filename)
            # checking if it is a file
            if os.path.isfile(f):
                with open(f, 'r') as file:
                    file_content = file.read()
                    data["content"] = filename + "\n"
                    data["content"] = data["content"] + "\n" + file_content
                #delete the file after sending it
                os.remove(f)
                #sending file contents to alert
                send_alert(url, data)
    except:
        print("error with checking Smuggler files")
        data["content"] = "There was an error checking Smuggler payloads directory."
        send_alert(error_discord_webhook_url, data)

def nuclei_alert(severity,finding,domain):
    #dynamic alert message for real findings vs informationals
    intro_message = "Nuclei has detected a vulnerable host"
    # webhook urls
    url = ""
    if severity == "info":
        intro_message = "Nuclei has found information about"
        url = "https://discord.com/api/webhooks/{{{REPLACE}}}""
    elif severity == "low":
     url = "https://discord.com/api/webhooks/{{{REPLACE}}}""
    elif severity == "medium":
        url = "https://discord.com/api/webhooks/{{{REPLACE}}}""
    elif severity == "high":
        url = "https://discord.com/api/webhooks/{{{REPLACE}}}""
    elif severity == "critical":
        url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": f"---------------------------\n{intro_message}: {domain}"
    }

    #cycle through the findings and add it to the alert message
    for line in finding:
        data["content"] = data["content"] + "\n" + line

    # many results are too big for discord's 2000 character limit. Cut it off before then manually.
    data["content"] = data["content"][0:1800]
    # send message for alert
    send_alert(url, data)

def initialize_watched_domains_alert(subdomains,wildcard_domain):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": f"---------------------------\nA new watched domain has been initialized: {wildcard_domain}\nSubdomains:"
    }

    #cycle through the findings and add it to the alert message
    for sub in subdomains:
        data["content"] = data["content"] + "\n" + sub

    data["content"] = data["content"] + "\n\n" + "Running Scans on these domains..."

    # many results are too big for discord's 2000 character limit. Cut it off before then manually.
    data["content"] = data["content"][0:1800]
    # send message for alert
    send_alert(url, data)

def watched_domain_new_sub_alert(subdomains,wildcard_domain):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": f"---------------------------\n{wildcard_domain} has new subdomains!\nNew Subdomains:"
    }

    # cycle through the findings and add it to the alert message
    for sub in subdomains:
        data["content"] = data["content"] + "\n" + sub

    data["content"] = data["content"] + "\n\n" + "Running Scans on these domains..."
    # send message for alert
    send_alert(url, data)

def version_number_alert(domain, all_vulnerabilities):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": ""
                   f"""---------------------------\n{domain} has software with known vulnerabilities!"""
    }

    #loop through all the vulnerabilities for this piece of software and pretty it up for discord.
    for affected_package in all_vulnerabilities:
        data["content"] = data["content"] + f"\n--------------\n{affected_package}\n--------------"
        for x in all_vulnerabilities[affected_package]:
            print(f'{affected_package}: {x[0]}')
            data["content"] = data["content"] + f"""
CVE ID:{x[0]['CVE ID']}
Severity:{x[0]['Severity']}
Description:{x[0]['Description']}
Link:{x[0]['Link']}
"""
    #many results are too big for discord's 2000 character limit. Cut it off before then manually.
    data["content"] = data["content"][0:1800]
    send_alert(url, data)

def scan_status_alert(status_update):
    # webhook url
    url = "https://discord.com/api/webhooks/{{{REPLACE}}}""

    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": status_update
    }

    data["content"] = data["content"][0:1800]
    send_alert(url, data)

def send_error_alert(error_message):
    # for all params, see https://discordapp.com/developers/docs/resources/webhook#execute-webhook
    data = {
        "content": f"---------------------------\nAutomation scripts encountered an error:"
    }
    data["content"] = data["content"] + "\n" + error_message
    send_alert(error_discord_webhook_url, data)