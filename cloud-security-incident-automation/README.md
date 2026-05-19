# Cloud Security Breach Detection and Jira Incident Automation

## Objectives

This project simulates unauthorized access attempts against cloud object storage, analyzes generated access logs, detects potential security breaches, categorizes incident severity, and automatically creates Jira-style security incident tickets.

## Tools Used

- Python 3.12
- JSON
- Bash
- Linux
- Requests
- Simulated AWS S3 access logs
- Simulated Jira issue generation
- Git/GitHub

## Key Skills Demonstrated

- Cloud security breach detection
- Security log generation and parsing
- Incident severity classification
- Automated incident response workflow
- Jira ticket payload generation
- Python-based security automation
- Structured project organization
- Troubleshooting outdated lab instructions

## Project Workflow

1. Generate simulated cloud storage access logs.
2. Detect suspicious activity such as unauthorized IPs, unauthorized users, sensitive object access, failed authentication, and unusual activity patterns.
3. Create structured breach reports in JSON format.
4. Generate Jira-style incident tickets for each detected breach.
5. Save reports for audit and investigation.

## Troubleshooting Log

- Replaced global pip installation with Python virtual environment to avoid Ubuntu externally managed environment errors.
- Removed unnecessary packages: datetime, json-logging, and boto3-stubs.
- Fixed unstable relative paths using project-root-safe paths.
- Fixed duplicate breach ID risk by adding sequential breach numbering.
- Completed incomplete Jira integration script logic.
- Replaced fake Jira custom fields with portfolio-safe payload metadata.
- Updated Jira API reference from `/rest/api/2` style to `/rest/api/3` style in simulated output.

## Files

- `config/aws_config.json`
- `config/jira_config.json`
- `scripts/simulate_breach.py`
- `scripts/breach_detector.py`
- `scripts/jira_integration.py`
- `logs/*.json`
