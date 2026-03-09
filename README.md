# Enterprise_Security_System
Enterprise Vulnerability Scanner is a web-based cybersecurity tool designed to identify potential security weaknesses in a target host or network. The application performs automated scanning to detect open ports, running services, and associated vulnerabilities, and then generates structured reports for security analysis and remediation.


GitHub homepage documentation.
Contains:
Project description
Features
Installation
Usage
Screenshots
Author

Example heading:
# Enterprise Vulnerability Scanner
A web-based cybersecurity tool that scans network hosts,
identifies vulnerabilities, and generates professional reports.

Enterprise-Vulnerability-Scanner
│
├── app.py
├── scanner.py
├── report_generator.py
├── requirements.txt
├── README.md
│
├── static
│   │
│   ├── css
│   │   └── style.css
│   │
│   ├── js
│   │   └── script.js
│   │
│   └── reports
│       ├── pdf
│       └── excel
│
├── templates
│   │
│   └── index.html
│
├── scans
│   └── scan_results.json
│
└── docs
    └── project_report.pdf

    
-----------------------------------------------------------------
 
 📄 File Explanation
 
------app.py

Main Flask application.
Handles:
API routes
Scan request
Download reports
Frontend communication

-----scanner.py

Core network scanning logic.
Handles:
Nmap execution
Service detection
Vulnerability mapping
CVE lookup

------report_generator.py

Generates professional reports.
Features:
PDF report
Excel report
CVE table
Owner details
Scan summary


--------requirements.txt

Project dependencies.
flask
python-nmap
pandas
openpyxl
reportlab

Install with:
pip install -r requirements.txt

---------------------------------------------------
--------------🌐 Frontend

templates/index.html
Main dashboard UI.

Contains:
Target IP input
Owner details
Scan button
Terminal output
Critical vulnerability alert
Download buttons

---------static/css/style.css

Contains styling for:
Dark UI
Terminal
Buttons
Alerts
Dashboard layout

