# cra_rule_checker.py
from version_checker import check_version
from vulnerability_scanner import scan_vulnerabilities
from packaging import version
from sbom_parser import parse_sbom

from werkzeug.utils import secure_filename
import traceback
import json

'''
def getLatestVersion(sbom_data):
    global LATEST_VERSIONS
    LATEST_VERSIONS = check_version(sbom_data)

    print('Line: 9 from cra_rule_checker.py:')
    print(LATEST_VERSIONS)
'''

###
def compare_versions(current, latest):
    try:
        #Security check if both current and latest are valid
        if not current or not latest:
            return False
        if current.lower() == 'unknown' or latest.lower() == 'unknown':
            return False
        
        return version.parse(current) >= version.parse(latest)
    except Exception as e:
        print("ERROR IN THE COMPARISON OF THE VERSIONS (CRA_RULE_CHECKER)")
        print(f"Current: {current}, Latest: {latest}")
        print(f"Exception: {e}")
        traceback.print_exc()
        return False
###

#Rule 1
###Input the results from the vulnerability_scanner.py
def check_no_critical_cves(component):
    print("Component ENRICHED line 35 cra_rule_checker.py: ")
    print(component)

    for cve in component.get("cves", []):
        if cve.get("cvss", 0) >= 7.0:
            #ONLY THE FIRST CVE that's critical is being returned
            return {
                "status": "fail",
                "justification": f"{cve['cve']} has CVSS {cve['cvss']}"
            }
    return {"status": "pass", "justification": "No threat found"}

    
#Rule 2
def check_license_present(component):
    if component.get("license"):
        return {"status": "pass", "justification": None}
    else:
        return {
            "status": "fail",
            "justification": "License field is missing"
        }

#Rule 3
def check_up_to_date(component):
    current = component.get("version")
    latest = component.get("latest_version")

    if not latest:
        return {"status": "not_applicable", "justification": "No version data for component"}

    if compare_versions(current, latest) == True:
        return {"status": "pass", "justification": "Up-to-date"}
    else:
        return {
            "status": "fail",
            "justification": f"{current} is older than latest {latest}"
        }

#Rule 4
def check_update_policy(component):
    if component.get("updatePolicy"):
        return {"status": "pass", "justification": "Update policy available"}
    else:
        return {
            "status": "fail",
            "justification": "No update policy info in SBOM"
        }

########################################################################

#Rule 5
def extract_metadata(file_path):
    #Take out the metadata from it if it's present
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            sbom_data = json.load(f)

        metadata = sbom_data.get("metadata", {})
        component = metadata.get("component", {})
        model_name = component.get("name")

        if model_name and model_name.strip():
            return {"status": "pass", "justification": "Name of model present"}
        else:
            return {
                "status": "fail",
                "justification": "Model name missing in SBOM metadata"
            }

    except (json.JSONDecodeError, FileNotFoundError, TypeError) as e:
        print(f"Error reading SBOM file: {e}")
        return {
            "status": "fail",
            "justification": "Error reading or parsing SBOM file"
        }
    


def summarize_cra_results(rule_results):
    # Initialize counters for each rule
    rule_stats = {
        "check_no_critical_cves": {"name": "Known Vulnerabilities", "pass": 0, "total": 0},
        "check_license_present": {"name": "License Presence", "pass": 0, "total": 0},
        "check_up_to_date": {"name": "Up-to-Date Components", "pass": 0, "total": 0},
        "check_update_policy": {"name": "Update Policy", "pass": 0, "total": 0},
        "extract_metadata": {"name": "Metadata Presence", "pass": 0, "total": 0},
    }

    # Count results for each rule
    for result in rule_results:
        rule = result.get("rule")
        status = result.get("status")
        if rule in rule_stats:
            rule_stats[rule]["total"] += 1
            if status == "pass":
                rule_stats[rule]["pass"] += 1

    # Build criteria list and calculate score
    criteria = []
    total_passed = 0
    total_checks = 0

    for rule, data in rule_stats.items():
        total = data["total"]
        passed = data["pass"]
        if total == 0:
            percentage = 0  # Not applicable, but count as 0%
        else:
            percentage = round((passed / total) * 100)

        criteria.append({
            "name": data["name"],
            "status": percentage
        })

        total_passed += passed
        total_checks += total

    # Overall CRA score
    score = round((total_passed / total_checks) * 100) if total_checks else 0

    return {
        "score": score,
        "criteria": criteria
    }

def run_cra_checks(file_path):
    #1. Parse the file using the path parameter and continue as usual
    sbom_data = parse_sbom(file_path)

    cveRes = scan_vulnerabilities(sbom_data)

    # For each component, attach relevant CVEs
    for comp in sbom_data:
        name = comp["component"]
        comp["cves"] = [cve for cve in cveRes if cve["component"] == name]


    versionRes = check_version(sbom_data)

    for comp in sbom_data:
        for ver in versionRes:
            if comp["component"] == ver["component"]:
                comp["latest_version"] = ver["latest_version"]
                break
    
    #NOW sbom_data LOOKS DIFFERENT - ITS ENRICHED + CVE + VERSIONS!!!
    results = []   

    for comp in sbom_data:
        # rule_fn = check_no_critical_cves => rule_fn = check_license_present etc.
        for rule_fn in [check_no_critical_cves, check_license_present, check_up_to_date, check_update_policy]:
            #calling the rule and sending the component to it
            result = rule_fn(comp)


            results.append({
                "component": comp.get("component"),
                #gives you the name of the function as a string 
                #check_no_critical_cves.__name__  # → "check_no_critical_cves"
                "rule": rule_fn.__name__,
                "status": result["status"],
                "justification": result["justification"]
            })
    
    print("SBOM_DATA ABOVE FINISHED")
    
    #2. Take the metadata out from the original file
    results.append({
        "component": "sbom_metadata",
        "rule": "extract_metadata",
        # takes all key-value pairs from the dictionary returned by check_model_designation() 
        # and inserts them into the dictionary you’re building
        **extract_metadata(file_path)
    })
    
    print("THE OUTPUT")
    print(results)

    '''
    That's the output from the function
    return {
        "score": score,
        "criteria": criteria
    }
    '''
    endRes = summarize_cra_results(results)

    print("SCORE")
    print(endRes)

    return endRes
