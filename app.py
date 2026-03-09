from flask import Flask, render_template, request, jsonify, send_file
import nmap
import pandas as pd
import os
from report_generator import generate_pdf_report

app = Flask(__name__)

scanner = nmap.PortScanner()

REPORT_FOLDER = "reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)

scan_results = []

owner_name = ""
phone_number = ""

# Vulnerability database
vulnerability_info = {

22:{
"name":"SSH Username Enumeration",
"severity":"Critical",
"cve":"CVE-2018-15473",
"cvss":"7.5",
"consequence":"Attackers can enumerate valid usernames which helps brute-force attacks.",
"remediation":"Update OpenSSH to the latest version and disable username enumeration."
},

23:{
"name":"Telnet Service Exposure",
"severity":"Critical",
"cve":"CVE-1999-0617",
"cvss":"9.0",
"consequence":"Telnet transmits credentials in plaintext allowing attackers to intercept authentication.",
"remediation":"Disable Telnet service and use SSH for secure remote access."
},

80:{
"name":"Apache Path Traversal",
"severity":"High",
"cve":"CVE-2021-41773",
"cvss":"7.5",
"consequence":"Attackers may access restricted files on the web server.",
"remediation":"Update Apache to the patched version."
},

443:{
"name":"OpenSSL Infinite Loop",
"severity":"Medium",
"cve":"CVE-2022-0778",
"cvss":"5.9",
"consequence":"Attackers can cause denial-of-service through crafted certificates.",
"remediation":"Update OpenSSL to latest version."
},

3389:{
"name":"BlueKeep RDP Vulnerability",
"severity":"Critical",
"cve":"CVE-2019-0708",
"cvss":"9.8",
"consequence":"Remote code execution possible without authentication.",
"remediation":"Install Microsoft security patch."
}
}

def detect_vulnerability(port):

    if port in vulnerability_info:
        return vulnerability_info[port]

    return {
        "name":"Unknown Service Exposure",
        "severity":"Low",
        "cve":"N/A",
        "cvss":"N/A",
        "consequence":"Open port increases attack surface.",
        "remediation":"Close unused ports using firewall rules."
    }


@app.route("/")
def home():
    return render_template("index.html")


# 🔎 SCAN ROUTE
@app.route("/scan", methods=["POST"])
def scan():

    global scan_results, owner_name, phone_number

    scan_results = []

    data = request.json

    ip = data["ip"]
    owner_name = data["owner"]
    phone_number = data["phone"]

    scanner.scan(ip, arguments="-sV")

    for host in scanner.all_hosts():

        for proto in scanner[host].all_protocols():

            ports = scanner[host][proto].keys()

            for port in ports:

                service = scanner[host][proto][port]["name"]

                vuln = detect_vulnerability(port)

                scan_results.append({

                    "host_id":host,
                    "port":port,
                    "service":service,
                    "vulnerability":vuln["name"],
                    "severity":vuln["severity"],
                    "cve":vuln["cve"],
                    "cvss":vuln["cvss"],
                    "consequence":vuln["consequence"],
                    "remediation":vuln["remediation"]

                })

    critical_count = len([v for v in scan_results if v["severity"]=="Critical"])

    return jsonify({
        "status":"completed",
        "critical":critical_count
    })


# 📊 EXCEL DOWNLOAD
@app.route("/download_excel")
def download_excel():

    df = pd.DataFrame(scan_results)

    file_path = f"{REPORT_FOLDER}/scan_report.xlsx"

    df.to_excel(file_path,index=False)

    return send_file(file_path,as_attachment=True)


# 📄 PDF DOWNLOAD (WITH OWNER + PHONE)
@app.route("/download_pdf/<ip>")
def download_pdf(ip):

    file_path = f"{REPORT_FOLDER}/scan_report_{ip}.pdf"

    generate_pdf_report(
        scan_results,
        ip,
        owner_name,
        phone_number
    )

    return send_file("vulnerability_report.pdf",as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)