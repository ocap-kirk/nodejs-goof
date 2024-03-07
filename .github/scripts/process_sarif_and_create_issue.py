import json
import os
import requests

def create_github_issue(title, body, token):
    """Create an issue on GitHub."""
    url = "https://api.github.com/repos/{owner}/{repo}/issues".format(owner="ocap-kirk", repo="nodejs-goof")
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    data = {"title": title, "body": body}
    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 201:
        print("Issue created successfully: ", response.json()["html_url"])
    else:
        print("Failed to create issue. Response: ", response.text)

def process_sarif_and_create_issue(sarif_file_path, github_token):
    with open(sarif_file_path, 'r') as file:
        sarif_data = json.load(file)
    
    #log the SARIF file
    print(json.dumps(sarif_data, indent=4))
    
    issue_body = ""
    results_found = False

    for run in sarif_data["runs"]:
        for result in run["results"]:
            results_found = True
            rule_id = result["ruleId"]
            message_text = result["message"]["text"]
            locations = json.dumps(result.get("locations"), indent=4)
            fixes = json.dumps(result.get("fixes"), indent=4) if "fixes" in result else "No fixes provided."

            issue_body += f"### Rule ID: {rule_id}\n" \
                          f"#### Message: {message_text}\n" \
                          f"```json\nLocations: {locations}\n```\n" \
                          f"```json\nFixes: {fixes}\n```\n\n"

    if results_found:
        issue_title = "Multiple Issues Found" if sarif_data["runs"][0]["results"] else "Security Scan Results"
    else:
        issue_title = "Security Scan Results"
        issue_body = "No specific security issues found."

    create_github_issue(issue_title, issue_body, github_token)

if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SARIF_FILE_PATH = "snyk_output.sarif"
    process_sarif_file(SARIF_FILE_PATH, GITHUB_TOKEN)


