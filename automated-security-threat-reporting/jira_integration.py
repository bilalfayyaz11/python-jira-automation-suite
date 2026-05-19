import json
import datetime
from pathlib import Path


class JiraIntegration:
    def __init__(self, project_key="SEC"):
        self.project_key = project_key
        self.created_issues = []

    def create_security_issue(self, alert_data, risk_level):
        priority_map = {
            "High": "Highest",
            "Medium": "High",
            "Low": "Medium",
            "Informational": "Low"
        }

        issue_key = f"{self.project_key}-{1001 + len(self.created_issues)}"

        issue = {
            "issue_key": issue_key,
            "project": self.project_key,
            "summary": f"Security Alert: {alert_data.get('name', 'Unknown Vulnerability')}",
            "priority": priority_map.get(risk_level, "Medium"),
            "risk_level": risk_level,
            "labels": ["security", "automated", f"risk-{risk_level.lower()}"],
            "description": self.format_description(alert_data, risk_level),
            "created_at": datetime.datetime.now(datetime.UTC).isoformat()
        }

        self.created_issues.append(issue)
        print(f"Created Jira-style issue: {issue_key} | Risk: {risk_level} | Priority: {issue['priority']}")
        return issue_key

    def format_description(self, alert_data, risk_level):
        return f"""
Automated Security Alert

Vulnerability: {alert_data.get('name', 'Unknown')}
Risk Level: {risk_level}
Affected URL: {alert_data.get('url', 'N/A')}
Parameter: {alert_data.get('param', 'N/A')}

Description:
{alert_data.get('description', 'No description available')}

Evidence:
{alert_data.get('evidence', 'No evidence available')}

Attack:
{alert_data.get('attack', 'No attack vector recorded')}

Solution:
{alert_data.get('solution', 'No solution provided')}

Reference:
{alert_data.get('reference', 'No reference available')}

Detection Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Detected By: OWASP ZAP Automated Scanner
        """.strip()

    def bulk_create_issues(self, security_report):
        for risk_key, risk_level in [
            ("high_risk", "High"),
            ("medium_risk", "Medium")
        ]:
            for alert in security_report.get(risk_key, []):
                self.create_security_issue(alert, risk_level)

        return self.created_issues

    def save_issue_report(self, filename="jira_issues_report.json"):
        with open(filename, "w") as f:
            json.dump(
                {
                    "total_issues_created": len(self.created_issues),
                    "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    "issues": self.created_issues
                },
                f,
                indent=2
            )

        print(f"Saved Jira-style issue report to {filename}")


if __name__ == "__main__":
    report_file = Path("security_report.json")

    if not report_file.exists():
        print("Security report not found. Run zap_scanner.py first.")
        raise SystemExit(1)

    with open(report_file, "r") as f:
        report = json.load(f)

    jira_client = JiraIntegration(project_key="SEC")
    created = jira_client.bulk_create_issues(report)
    jira_client.save_issue_report()

    print(f"Successfully created {len(created)} Jira-style security issues.")
