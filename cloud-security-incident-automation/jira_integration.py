#!/usr/bin/env python3
"""
Jira Integration for Security Breach Management
Creates simulated Jira issues for detected cloud security incidents.
"""

import json
import datetime
import base64
import glob
import os
from pathlib import Path


class JiraSecurityIntegration:
    def __init__(self, jira_config_file: str):
        with open(jira_config_file, "r") as f:
            self.config = json.load(f)

        self.base_url = self.config["jira_url"]
        self.auth_header = self.create_auth_header()
        self.demo_mode = True
        self.created_issues = []

    def create_auth_header(self) -> dict:
        auth_string = f"{self.config['username']}:{self.config['api_token']}"
        encoded_auth = base64.b64encode(auth_string.encode()).decode()

        return {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def load_breach_report(self, report_file: str) -> dict | None:
        try:
            with open(report_file, "r") as f:
                report = json.load(f)

            print(f"📊 Loaded breach report with {report['total_breaches']} breaches")
            return report

        except FileNotFoundError:
            print(f"❌ Error: Report file {report_file} not found")
            return None

        except json.JSONDecodeError as e:
            print(f"❌ Error parsing report file: {e}")
            return None

    def create_jira_issue_payload(self, breach: dict) -> dict:
        priority = self.config["priority_mapping"].get(breach["severity"], "Medium")
        description = self.format_breach_description(breach)
        summary = f"Security Breach Detected: {breach['severity']} - {breach['source_ip']}"

        payload = {
            "fields": {
                "project": {"key": self.config["project_key"]},
                "summary": summary,
                "description": description,
                "issuetype": {"name": self.config["issue_type"]},
                "priority": {"name": priority},
                "labels": self.config["labels"] + [f"severity-{breach['severity'].lower()}"],
                "components": [{"name": comp} for comp in self.config["components"]],
                "breach_id": breach["breach_id"],
                "source_ip": breach["source_ip"],
                "affected_resource": breach["bucket"]
            }
        }

        if self.config.get("assignee"):
            payload["fields"]["assignee"] = {"name": self.config["assignee"]}

        return payload

    def format_breach_description(self, breach: dict) -> str:
        return f"""
*SECURITY BREACH ALERT*

*Breach ID:* {breach['breach_id']}
*Detection Time:* {breach['timestamp']}
*Severity:* {breach['severity']}

*Incident Details:*
• Source IP: {breach['source_ip']}
• User: {breach['user']}
• Affected Resource: {breach['bucket']}
• Object Accessed: {breach['object_key']}
• Action Performed: {breach['action']}
• HTTP Status: {breach['status_code']}

*Security Issues Detected:*
{self.format_detected_issues(breach['detected_issues'])}

*Impact Assessment:*
{breach['impact_assessment']}

*Recommended Actions:*
{self.format_recommended_actions(breach['recommended_actions'])}

*Investigation Notes:*
• Review access logs for the specified time period
• Verify whether this was authorized activity
• Check for additional suspicious activity from the same source
• Update security policies if necessary

*Automated Detection:* This issue was created automatically by the cloud security monitoring workflow.
        """.strip()

    def format_detected_issues(self, issues: list[str]) -> str:
        descriptions = {
            "unauthorized_ip": "Unauthorized IP address access",
            "unauthorized_user": "Unauthorized user account",
            "suspicious_object": "Access to sensitive or confidential files",
            "failed_auth": "Authentication or authorization failure",
            "unusual_activity": "Unusual access pattern"
        }

        return "\n".join([f"• {descriptions.get(issue, issue)}" for issue in issues])

    def format_recommended_actions(self, actions: list[str]) -> str:
        return "\n".join([f"• {action}" for action in actions])

    def create_jira_issue(self, breach: dict) -> dict:
        payload = self.create_jira_issue_payload(breach)

        issue_key = f"{self.config['project_key']}-{len(self.created_issues) + 1001}"

        mock_response = {
            "key": issue_key,
            "id": f"1000{len(self.created_issues) + 1}",
            "self": f"{self.base_url}/rest/api/3/issue/{issue_key}",
            "created": datetime.datetime.now(datetime.UTC).isoformat(),
            "status": "Open"
        }

        self.created_issues.append({
            "breach_id": breach["breach_id"],
            "jira_key": issue_key,
            "severity": breach["severity"],
            "created_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "payload": payload
        })

        print(f"🎫 Created Jira issue: {issue_key} for breach {breach['breach_id']}")
        print(f"   Severity: {breach['severity']} | Priority: {payload['fields']['priority']['name']}")

        return mock_response

    def process_breach_report(self, report: dict) -> list[dict]:
        created_issues = []

        print(f"🎫 Processing {report['total_breaches']} breaches for Jira issue creation...")
        print("-" * 60)

        for index, breach in enumerate(report["breaches"], 1):
            print(f"\nProcessing breach {index}/{len(report['breaches'])}: {breach['breach_id']}")

            issue_result = self.create_jira_issue(breach)

            created_issues.append({
                "breach_id": breach["breach_id"],
                "jira_issue": issue_result,
                "severity": breach["severity"]
            })

        return created_issues

    def generate_jira_summary_report(self, created_issues: list[dict]) -> dict:
        summary = {
            "total_issues_created": len(created_issues),
            "creation_timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "severity_breakdown": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "issues": created_issues
        }

        for issue in created_issues:
            summary["severity_breakdown"][issue.get("severity", "LOW")] += 1

        return summary

    def save_jira_report(self, summary: dict, filename: str):
        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        with open(filename, "w") as f:
            json.dump(summary, f, indent=2)

        print(f"📋 Jira integration report saved to {filename}")

    def print_summary(self, summary: dict):
        print("\n" + "=" * 60)
        print("🎫 JIRA INTEGRATION SUMMARY")
        print("=" * 60)

        print(f"Total Issues Created: {summary['total_issues_created']}")
        print(f"High Priority Issues: {summary['severity_breakdown']['HIGH']}")
        print(f"Medium Priority Issues: {summary['severity_breakdown']['MEDIUM']}")
        print(f"Low Priority Issues: {summary['severity_breakdown']['LOW']}")

        if summary["issues"]:
            print("\nCreated Issues:")
            for issue in summary["issues"]:
                print(f"  • {issue['jira_issue']['key']} - {issue['severity']} severity")


def main():
    print("🎫 Starting Jira Security Integration")
    print("=" * 50)

    jira_integration = JiraSecurityIntegration("config/jira_config.json")

    report_files = glob.glob("logs/breach_report_*.json")

    if not report_files:
        print("❌ No breach reports found. Please run breach detection first.")
        return

    latest_report = max(report_files, key=os.path.getctime)
    print(f"📊 Processing breach report: {latest_report}")

    report = jira_integration.load_breach_report(latest_report)

    if not report:
        return

    created_issues = jira_integration.process_breach_report(report)
    summary = jira_integration.generate_jira_summary_report(created_issues)

    jira_report_filename = f"logs/jira_integration_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    jira_integration.save_jira_report(summary, jira_report_filename)
    jira_integration.print_summary(summary)


if __name__ == "__main__":
    main()
