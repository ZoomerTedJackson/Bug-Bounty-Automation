import requests
import re
import json

def find_cpes(search):
    base_url = "https://nvd.nist.gov/products/cpe/search/results"
    params = {
        "namingFormat": "2.3",
        "keyword": search
    }

    response = requests.get(base_url, params=params)
    content = response.text

    cpe_strings = re.findall(r'cpe:(.*?)<', content)
    if cpe_strings:
        return cpe_strings[0]
    else:
        return ""

def find_vulnerabilities_by_cpe(cpe_string):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cves = []
    reportable_severity = ["critical","high","medium"]
    url = f"{base_url}?cpeName=cpe:{cpe_string}"

    response = requests.get(url)
    if response.status_code != 200:
        return []
    try:
        data = response.json()
    except json.JSONDecodeError:
        return []

    for cve_item in data["vulnerabilities"]:
        all_cve_details = []

        cve_id = cve_item["cve"]["id"]
        description_text = cve_item["cve"]["descriptions"][0]["value"]
        '''
        check for severity, prioritizing newer CVSS versions.
        if it is lower than a medium severity then skip this item and don't bother logging it for an alert
        
        Note to self, change this so that it looks through all the returned CVEs and sends it in order of the CVSS score
        '''
        if "cvssMetricV31" in cve_item["cve"]["metrics"]:
            if cve_item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"].lower() not in reportable_severity:
                continue
            severity = f'{cve_item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]} - {cve_item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]}'
        elif "cvssMetricV30" in cve_item["cve"]["metrics"]:
            if cve_item["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"].lower() not in reportable_severity:
                continue
            severity = f'{cve_item["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseSeverity"]} - {cve_item["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]}'
        elif "cvssMetricV2" in cve_item["cve"]["metrics"]:
            if cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseSeverity"].lower() not in reportable_severity:
                continue
            severity = f'{cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseSeverity"]} - {cve_item["cve"]["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]}'
        else:
            continue
        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        all_cve_details.append({
            "CVE ID": cve_id,
            "Description": description_text,
            "Severity": severity,
            "Link": link
        })
        cves.append(all_cve_details)

    return cves

def escape_ansi(line):
    ansi = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi.sub('', line)
