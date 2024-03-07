import json
import os
import requests

def create_github_issue(title, body, token):
    """
    Creates a GitHub issue in a specified repository.

    This function constructs a POST request to the GitHub API to create a new issue
    with the provided title and body content. It requires a valid GitHub token for
    authorization. The function prints the URL of the newly created issue upon success
    or an error message upon failure.

    Parameters:
    - title (str): The title of the GitHub issue.
    - body (str): The detailed description (body) of the issue.
    - token (str): A GitHub Personal Access Token for authentication.
    """
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

def process_sarif_file(sarif_file_path, github_token):
    """
    Processes a SARIF file to create a GitHub issue based on its contents.

    This function reads a SARIF (Static Analysis Results Interchange Format) file to
    extract information about security issues found during a scan. It then formats this
    information into a markdown-compatible issue body. If any issues are found, it creates
    a single GitHub issue summarizing all findings. If no issues are found, it creates an
    issue indicating that no security issues were detected.

    The function also logs the entire content of the SARIF file for debugging purposes.

    Parameters:
    - sarif_file_path (str): The file path to the SARIF file to be processed.
    - github_token (str): A GitHub Personal Access Token for authenticating issue creation.
    """
    with open(sarif_file_path, 'r') as file:
        sarif_data = json.load(file)
    
    #log the SARIF file
    print(json.dumps(sarif_data, indent=4))
    
    issue_body = ""
    results_found = False

    # Extract findings from the SARIF data and format them for the GitHub issue body.
    for run in sarif_data["runs"]:
        for result in run["results"]:
            results_found = True
            rule_id = result["ruleId"]
            message_text = result["message"]["text"]
            locations = json.dumps(result.get("locations"), indent=4)
            fixes = json.dumps(result.get("fixes"), indent=4) if "fixes" in result else "No fixes provided."

            issue_body += f"### Rule ID: {rule_id}\n" \
                          f"#### Message: {message_text}\n" \
                          f"```json\n\"locations\": {locations}\n```\n" \
                          f"```json\n\"fixes\": {fixes}\n```\n\n"

    # Determine the issue title based on whether any results were found.
    if results_found:
        issue_title = "Multiple Issues Found" if sarif_data["runs"][0]["results"] else "Security Scan Results"
    else:
        issue_title = "Security Scan Results"
        issue_body = "No specific security issues found."

    # Create the GitHub issue with the compiled information.
    create_github_issue(issue_title, issue_body, github_token)

if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SARIF_FILE_PATH = "snyk_output.sarif"
    process_sarif_file(SARIF_FILE_PATH, GITHUB_TOKEN)


