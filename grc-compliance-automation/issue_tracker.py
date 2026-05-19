#!/usr/bin/env python3
"""
Issue Tracker for GRC Compliance
Creates and manages compliance violation tickets
"""

import json
import datetime
import os
from pathlib import Path

class IssueTracker:
    def __init__(self, issues_dir="reports/issues"):
        self.issues_dir = Path(issues_dir)
        self.issues_dir.mkdir(parents=True, exist_ok=True)
        self.issue_counter_file = self.issues_dir / "counter.txt"
        self.issues_index_file = self.issues_dir / "issues_index.json"
        self.load_issue_counter()
        self.load_issues_index()

    def load_issue_counter(self):
        try:
            with open(self.issue_counter_file, 'r') as f:
                self.current_issue_number = int(f.read().strip())
        except (FileNotFoundError, ValueError):
            self.current_issue_number = 1000

    def save_issue_counter(self):
        with open(self.issue_counter_file, 'w') as f:
            f.write(str(self.current_issue_number))

    def load_issues_index(self):
        try:
            with open(self.issues_index_file, 'r') as f:
                self.issues_index = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.issues_index = {}

    def save_issues_index(self):
        with open(self.issues_index_file, 'w') as f:
            json.dump(self.issues_index, f, indent=2)

    def generate_issue_id(self):
        issue_id = f"GRC-{self.current_issue_number}"
        self.current_issue_number += 1
        self.save_issue_counter()
        return issue_id

    def create_issue(self, check_result):
        issue_id = self.generate_issue_id()
        priority_mapping = {
            'Critical': 'Highest',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low'
        }
        priority = priority_mapping.get(check_result['severity'], 'Medium')
        issue = {
            'id': issue_id,
            'title': f"GRC Compliance Violation: {check_result['name']}",
            'description': self.format_issue_description(check_result),
            'priority': priority,
            'severity': check_result['severity'],
            'category': check_result['category'],
            'status': 'Open',
            'check_id': check_result['check_id'],
            'issues': check_result['issues'],
            'created_at': datetime.datetime.now().isoformat(),
            'updated_at': datetime.datetime.now().isoformat(),
            'assignee': 'Security Team',
            'labels': ['grc-compliance', 'security', check_result['category'].lower().replace(' ', '-')]
        }
        issue_file = self.issues_dir / f"{issue_id}.json"
        with open(issue_file, 'w') as f:
            json.dump(issue, f, indent=2)
        self.issues_index[issue_id] = {
            'title': issue['title'],
            'status': issue['status'],
            'priority': issue['priority'],
            'created_at': issue['created_at'],
            'check_id': issue['check_id']
        }
        self.save_issues_index()
        return issue

    def format_issue_description(self, check_result):
        description = f"""
**Compliance Check Failed**

**Check ID:** {check_result['check_id']}
**Check Name:** {check_result['name']}
**Category:** {check_result['category']}
**Severity:** {check_result['severity']}

**Issues Identified:**
"""
        for issue in check_result['issues']:
            description += f"- {issue}\n"
        description += f"""
**Details:** {check_result['details']}

**Timestamp:** {check_result['timestamp']}

**Recommended Actions:**
"""
        recommendations = self.get_recommendations(check_result['check_id'])
        for rec in recommendations:
            description += f"- {rec}\n"
        return description

    def get_recommendations(self, check_id):
        recommendations = {
            'SEC001': [
                'Review and update password policy configuration',
                'Ensure minimum password length is set to at least 8 characters',
                'Configure password aging policies',
                'Implement password complexity requirements'
            ],
            'SEC002': [
                'Disable root login via SSH',
                'Consider using key-based authentication instead of passwords',
                'Ensure SSH Protocol 2 is used',
                'Review SSH configuration file permissions'
            ],
            'SEC003': [
                'Correct file permissions on critical system files',
                'Review file ownership settings',
                'Implement regular permission audits',
                'Document approved permission changes'
            ],
            'SEC004': [
                'Start required services that are not running',
                'Configure services to start automatically on boot',
                'Investigate why services stopped',
                'Implement service monitoring alerts'
            ],
            'SEC005': [
                'Verify log rotation is working properly',
                'Check disk space for log directories',
                'Ensure logging services are running',
                'Review log file permissions and ownership'
            ]
        }
        return recommendations.get(check_id, ['Review the specific compliance requirement', 'Consult security documentation'])

    def create_issues_from_failed_checks(self, failed_checks):
        created_issues = []
        for check_result in failed_checks:
            issue = self.create_issue(check_result)
            created_issues.append(issue)
            print(f"Created issue {issue['id']}: {issue['title']}")
        return created_issues

    def list_open_issues(self):
        open_issues = []
        for issue_id, issue_info in self.issues_index.items():
            if issue_info['status'] == 'Open':
                open_issues.append({
                    'id': issue_id,
                    'title': issue_info['title'],
                    'priority': issue_info['priority'],
                    'created_at': issue_info['created_at']
                })
        return open_issues

    def get_issue_details(self, issue_id):
        issue_file = self.issues_dir / f"{issue_id}.json"
        try:
            with open(issue_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return None

    def update_issue_status(self, issue_id, new_status):
        issue = self.get_issue_details(issue_id)
        if issue:
            issue['status'] = new_status
            issue['updated_at'] = datetime.datetime.now().isoformat()
            issue_file = self.issues_dir / f"{issue_id}.json"
            with open(issue_file, 'w') as f:
                json.dump(issue, f, indent=2)
            self.issues_index[issue_id]['status'] = new_status
            self.save_issues_index()
            return True
        return False

    def generate_issues_report(self):
        total_issues = len(self.issues_index)
        open_issues = len([i for i in self.issues_index.values() if i['status'] == 'Open'])
        closed_issues = total_issues - open_issues
        priority_counts = {}
        for issue_info in self.issues_index.values():
            priority = issue_info['priority']
            priority_counts[priority] = priority_counts.get(priority, 0) + 1
        report = {
            'summary': {
                'total_issues': total_issues,
                'open_issues': open_issues,
                'closed_issues': closed_issues,
                'priority_breakdown': priority_counts
            },
            'open_issues': self.list_open_issues(),
            'generated_at': datetime.datetime.now().isoformat()
        }
        return report

if __name__ == "__main__":
    tracker = IssueTracker()
    example_failed_check = {
        'check_id': 'SEC001',
        'name': 'Password Policy Compliance',
        'category': 'Authentication',
        'severity': 'High',
        'status': 'FAIL',
        'issues': ['Password minimum length not configured', 'Password aging not set'],
        'details': 'Password policy configuration checked',
        'timestamp': datetime.datetime.now().isoformat()
    }
    issue = tracker.create_issue(example_failed_check)
    print(f"Created example issue: {issue['id']}")
    report = tracker.generate_issues_report()
    print(f"\nIssues Report:")
    print(f"Total Issues: {report['summary']['total_issues']}")
    print(f"Open Issues: {report['summary']['open_issues']}")
