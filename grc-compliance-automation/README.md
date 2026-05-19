# GRC Compliance Checklist Automation

## Objectives
- Automate execution of security compliance checks across a Linux system
- Generate structured compliance reports with pass/fail status per check
- Auto-create prioritized issue tickets for every compliance violation detected
- Demonstrate end-to-end GRC automation pipeline using Python and open-source tooling

## Tools Used
- Python 3.12 (stdlib only: json, os, subprocess, datetime, logging, pathlib, argparse)
- systemctl (systemd service management)
- Linux system files (/etc/ssh/sshd_config, /etc/login.defs, /etc/passwd, /var/log)
- JSON (configuration, reporting, issue storage)
- AWS EC2 Ubuntu 24.04

## Key Skills Demonstrated
- Security compliance automation against ISO 27001, NIST CSF, and CIS Controls
- Python OOP — modular class design (GRCChecker, IssueTracker, GRCAutomation)
- OS-level security auditing: SSH hardening, file permissions, password policy, service monitoring, log integrity
- Automated issue ticket generation with severity-based priority mapping
- Structured JSON reporting pipeline with persistent issue tracking
- Real-world compliance finding: PasswordAuthentication enabled on EC2 (SEC002 flagged and ticketed)

## Compliance Checks Implemented
| Check ID | Name | Category | Severity | Result |
|----------|------|----------|----------|--------|
| SEC001 | Password Policy Compliance | Authentication | High | PASS |
| SEC002 | SSH Configuration Security | Network Security | Critical | FAIL |
| SEC003 | File Permissions Audit | Access Control | Medium | PASS |
| SEC004 | Service Status Monitoring | System Monitoring | High | PASS |
| SEC005 | Log File Integrity | Logging | Medium | PASS |

**Compliance Rate: 80.0%**

## Troubleshooting Log
- **SEC002 FAIL (expected):** AWS EC2 instances have `PasswordAuthentication yes` set in `/etc/ssh/sshd_config` by default. The checker correctly flagged this as a Critical-priority issue and auto-created ticket GRC-1002.
- **Duplicate issues GRC-1000/1001/1002:** Result of running the automation script multiple times during testing. The issue tracker appends a new ticket per run by design — in production, a deduplication check by `check_id` would be added.
- **All stdlib imports:** No pip dependencies required. All modules (json, os, subprocess, datetime, logging, pathlib) are Python 3.12 built-ins.
