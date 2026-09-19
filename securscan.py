#!/usr/bin/env python3

import subprocess
import os
import ipaddress
import datetime
import re
import xml.etree.ElementTree as ET

BANNER = """
========================================
          SecureScan v1.0
   Vulnerability Assessment Tool
========================================
"""

def get_target():
    while True:
        target = input("[?] Enter authorized lab target IP: ").strip()

        try:
            ipaddress.ip_address(target)
            break
        except ValueError:
            print("[-] Invalid IP address.")

    confirm = input("[?] Do you have authorization to scan this target? (yes/no): ")

    if confirm.lower() != "yes":
        print("[-] Authorization required. Exiting.")
        exit()

    return target


def run_command(command, output_file):
    print("\n[+] Running:")
    print(" ".join(command))

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    with open(output_file, "w") as f:
        f.write(result.stdout)
        f.write(result.stderr)

    return result.returncode


def parse_vulnerabilities(xml_file):
    findings = []

    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[-] XML parsing error: {e}")
        return findings

    for script in root.findall(".//script"):
        output = script.get("output", "")
        script_id = script.get("id", "unknown")

        if not output:
            continue

        # Only report explicit vulnerability confirmation
        if not re.search(r"VULNERABLE|State:\s*VULNERABLE", output, re.I):
            continue

        cves = sorted(set(
            re.findall(r"CVE-\d{4}-\d{4,7}", output, re.I)
        ))

        risk = re.search(
            r"Risk factor:\s*(HIGH|MEDIUM|LOW|CRITICAL)",
            output,
            re.I
        )

        severity = risk.group(1).capitalize() if risk else "Unknown"

        findings.append({
            "script": script_id,
            "cve": ", ".join(cves) if cves else "N/A",
            "severity": severity,
            "evidence": output.strip()
        })

    return findings


def generate_report(target, service_file, vuln_file, findings):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    report_file = f"reports/SecureScan_Report_{timestamp}.txt"

    with open(report_file, "w") as f:

        f.write("========================================\n")
        f.write("          SecureScan Report\n")
        f.write("========================================\n\n")

        f.write(f"Target: {target}\n")
        f.write("Assessment Type: Authorized Lab Assessment\n")
        f.write(f"Date: {timestamp}\n\n")

        f.write("SERVICE ENUMERATION\n")
        f.write(f"Result File: {service_file}\n\n")

        f.write("VULNERABILITY ASSESSMENT\n")
        f.write(f"Result File: {vuln_file}\n\n")

        f.write("FINDINGS\n")
        f.write("----------------------------------------\n")

        if not findings:
            f.write("No automatically confirmed findings were identified.\n")

        for i, finding in enumerate(findings, 1):
            f.write(f"\nFinding {i}\n")
            f.write(f"Script: {finding['script']}\n")
            f.write(f"CVE: {finding['cve']}\n")
            f.write(f"Severity: {finding['severity']}\n")
            f.write("Evidence:\n")
            f.write(f"{finding['evidence']}\n")

            f.write("\nRemediation:\n")
            f.write(
                "Apply the appropriate vendor security updates, "
                "disable unnecessary vulnerable services/protocols, "
                "and perform a follow-up assessment.\n"
            )

        f.write("\nVALIDATION\n")
        f.write(
            "Perform a follow-up vulnerability assessment after remediation "
            "to verify that the finding is resolved.\n"
        )

        f.write("\nRESPONSIBLE USE\n")
        f.write(
            "SecureScan must only be used on systems where the user has "
            "explicit authorization to perform security testing.\n"
        )

    return report_file


def run_assessment(target):

    os.makedirs("scans", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("evidence", exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    service_file = f"scans/service_{timestamp}.txt"
    vuln_file = f"scans/vulnerability_{timestamp}.txt"
    vuln_xml = f"scans/vulnerability_{timestamp}.xml"

    print("\n[+] Starting service enumeration...")

    run_command(
        ["nmap", "-Pn", "-sV", target],
        service_file
    )

    print("\n[+] Starting authorized vulnerability assessment...")

    run_command(
        ["nmap", "-Pn", "--script", "vuln",
         "-oN", vuln_file,
         "-oX", vuln_xml,
         target],
        vuln_file
    )

    print("\n[+] Parsing Nmap results...")

    findings = parse_vulnerabilities(vuln_xml)

    report = generate_report(
        target,
        service_file,
        vuln_file,
        findings
    )

    print("\n========================================")
    print("           SCAN COMPLETE")
    print("========================================")

    print(f"Target: {target}")
    print(f"Confirmed findings: {len(findings)}")

    for finding in findings:
        print(
            f"- {finding['script']} | "
            f"{finding['cve']} | "
            f"{finding['severity']}"
        )

    print(f"\n[+] Report: {report}")
    print("[+] Assessment completed successfully.")


def main():

    print(BANNER)

    print("1. Start Vulnerability Assessment")
    print("2. Exit")

    choice = input("\nSelect option: ").strip()

    if choice == "1":
        target = get_target()
        run_assessment(target)

    else:
        print("[+] Exiting SecureScan.")


if __name__ == "__main__":
    main()
