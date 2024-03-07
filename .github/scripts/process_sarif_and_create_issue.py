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
        print("Issue created successfully.")
    else:
        print("Failed to create issue.")

def process_sarif_file(sarif_file_path, github_token):
    """Process SARIF file and create a GitHub issue based on the findings."""
    critical_issues_found = False
    issue_body = "### Critical Security Issues Found\n\n"

    with open(sarif_file_path) as f:
        sarif_data = json.load(f)

    #log the SARIF file
    print(json.dumps(sarif_data, indent=4))

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            if result.get("level") == "error":  # Assuming 'error' level indicates critical issues
                critical_issues_found = True
                rule_id = result.get("ruleId")
                message = result.get("message", {}).get("text")
                issue_body += f"- **Rule ID**: {rule_id}, **Message**: {message}\n"

    if not critical_issues_found:
        issue_body = "No Critical Security Issues Found"

    create_github_issue("Security Scan Results", issue_body, github_token)

if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SARIF_FILE_PATH = "snyk_output.sarif"
    process_sarif_file(SARIF_FILE_PATH, GITHUB_TOKEN)
