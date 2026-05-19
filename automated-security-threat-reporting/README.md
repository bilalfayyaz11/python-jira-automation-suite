# Automated Cybersecurity Threat Reporting with OWASP ZAP

## Objectives

This project builds an automated cybersecurity threat detection and reporting workflow using OWASP ZAP, Python, Flask, and Jira-style incident reporting. It scans a deliberately vulnerable local web application, detects web application security issues, generates structured reports, and creates automated incident records for security teams.

## Tools Used

- Python 3.12
- Flask
- OWASP ZAP 2.16.1
- ZAP Python API
- Requests
- Jira-style incident automation
- JSON
- Bash
- Linux
- Java Runtime

## Key Skills Demonstrated

- Web application vulnerability testing
- OWASP ZAP automation
- SQL injection simulation
- Cross-site scripting simulation
- Automated threat detection
- Security report generation
- Incident priority mapping
- Jira-style ticket automation
- DevSecOps workflow design
- Python security scripting

## Project Workflow

1. Launch a vulnerable Flask web application on localhost.
2. Start OWASP ZAP in daemon mode.
3. Spider and actively scan the target application.
4. Generate a structured security report.
5. Simulate Jira-style security incident creation for high and medium risk findings.
6. Save scan logs, threat reports, and incident records for review.

## Troubleshooting Log

- Installed missing Java runtime required by OWASP ZAP.
- Installed missing Python pip and virtual environment tooling.
- Replaced global pip usage with a Python virtual environment.
- Updated OWASP ZAP from outdated 2.14.0 to 2.16.1.
- Fixed ZAP installer issue by running installer with sudo.
- Changed vulnerable Flask app host from `0.0.0.0` to `127.0.0.1` for safer localhost-only testing.
- Changed Flask debug mode from `True` to `False`.
- Used demo-mode Jira-style reporting to avoid credential exposure and keep the project reproducible.
- Added automated JSON reports and execution logs for auditability.

## Files

- `vulnerable_app.py`
- `zap_scanner.py`
- `jira_integration.py`
- `automated_threat_detection.py`
- `security_report.json`
- `jira_issues_report.json`
- `threat_report.json`
- `automated_jira_issues.json`
- `threat_detection.log`
