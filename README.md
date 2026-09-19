# SecureScan v1.0

SecureScan is a Python-based Vulnerability Assessment and Reporting
tool that uses Nmap to perform authorized security assessments.

## Features

- Target IP validation
- Authorization confirmation before scanning
- Service and version enumeration
- Nmap NSE vulnerability assessment
- SMB vulnerability checks
- FTP vulnerability checks
- HTTP vulnerability checks
- SSH-related checks
- DNS-related checks
- Vulnerability finding detection
- CVE information when available
- Severity classification
- Scan evidence storage
- Automatic vulnerability report generation
- Remediation recommendations
- Follow-up validation guidance

## Workflow

Target Validation
        ↓
Service & Version Enumeration
        ↓
Vulnerability Assessment
        ↓
Finding Detection
        ↓
CVE / Severity / Evidence
        ↓
Remediation
        ↓
Automatic Report

## Requirements

- Kali Linux or Debian-based Linux
- Python 3
- Nmap

## Installation

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd Securscan
