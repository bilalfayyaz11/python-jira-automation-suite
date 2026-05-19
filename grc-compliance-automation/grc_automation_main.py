#!/usr/bin/env python3
"""
Main GRC Automation Script
Combines compliance checking with automated issue reporting
"""

import sys
import os
import json
from pathlib import Path

sys.path.append('checks')
sys.path.append('reports')

from grc_checker import GRCChecker
from issue_tracker import IssueTracker

class GRCAutomation:
    def __init__(self):
        self.checker = GRCChecker()
        self.tracker = IssueTracker()
        self.results = []

    def run_compliance_scan(self):
        print("Starting GRC Compliance Automation...")
        print("=" * 50)
        print("1. Running compliance checks...")
        self.results = self.checker.run_all_checks()
        report = self.checker.generate_report()
        print(f"\nCompliance Scan Results:")
        print(f"- Total Checks: {report['summary']['total_checks']}")
        print(f"- Passed: {report['summary']['passed']}")
        print(f"- Failed: {report['summary']['failed']}")
        print(f"- Errors: {report['summary']['errors']}")
        print(f"- Compliance Rate: {report['summary']['compliance_rate']}")
        failed_checks = self.checker.get_failed_checks()
        if failed_checks:
            print(f"\n2. Creating issues for {len(failed_checks)} failed checks...")
            created_issues = self.tracker.create_issues_from_failed_checks(failed_checks)
            print(f"\nCreated Issues:")
            for issue in created_issues:
                print(f"- {issue['id']}: {issue['title']} (Priority: {issue['priority']})")
        else:
            print("\n2. No compliance violations found - no issues created.")
        self.save_detailed_report(report)
        return report, failed_checks

    def save_detailed_report(self, report):
        report_file = f"reports/grc_report_{report['generated_at'][:10]}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\nDetailed report saved to: {report_file}")

    def show_open_issues(self):
        open_issues = self.tracker.list_open_issues()
        if not open_issues:
            print("No open compliance issues found.")
            return
        print(f"\nOpen Compliance Issues ({len(open_issues)}):")
        print("-" * 50)
        for issue in open_issues:
            print(f"ID: {issue['id']}")
            print(f"Title: {issue['title']}")
            print(f"Priority: {issue['priority']}")
            print(f"Created: {issue['created_at'][:19]}")
            print("-" * 30)

    def show_issue_details(self, issue_id):
        issue = self.tracker.get_issue_details(issue_id)
        if not issue:
            print(f"Issue {issue_id} not found.")
            return
        print(f"\nIssue Details: {issue_id}")
        print("=" * 50)
        print(f"Title: {issue['title']}")
        print(f"Status: {issue['status']}")
        print(f"Priority: {issue['priority']}")
        print(f"Severity: {issue['severity']}")
        print(f"Category: {issue['category']}")
        print(f"Created: {issue['created_at']}")
        print(f"Assignee: {issue['assignee']}")
        print(f"\nDescription:\n{issue['description']}")

    def close_issue(self, issue_id):
        if self.tracker.update_issue_status(issue_id, 'Closed'):
            print(f"Issue {issue_id} has been closed.")
        else:
            print(f"Failed to close issue {issue_id}. Issue not found.")

    def generate_summary_report(self):
        if not self.results:
            print("No compliance scan results available. Run a scan first.")
            return
        compliance_report = self.checker.generate_report()
        issues_report = self.tracker.generate_issues_report()
        print("\nGRC Automation Summary Report")
        print("=" * 50)
        print(f"\nCompliance Status:")
        print(f"- Compliance Rate: {compliance_report['summary']['compliance_rate']}")
        print(f"- Total Checks: {compliance_report['summary']['total_checks']}")
        print(f"- Failed Checks: {compliance_report['summary']['failed']}")
        print(f"\nIssue Tracking Status:")
        print(f"- Total Issues: {issues_report['summary']['total_issues']}")
        print(f"- Open Issues: {issues_report['summary']['open_issues']}")
        print(f"- Closed Issues: {issues_report['summary']['closed_issues']}")

if __name__ == "__main__":
    automation = GRCAutomation()
    report, failed = automation.run_compliance_scan()
    automation.show_open_issues()
    automation.generate_summary_report()
