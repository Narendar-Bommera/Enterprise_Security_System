import socket

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS"
}

vulnerabilities = {
    "SSH": ("CVE-2018-15473", 7.5, "High"),
    "HTTP": ("CVE-2021-41773", 9.8, "Critical"),
    "HTTPS": ("CVE-2016-2107", 7.4, "High"),
    "FTP": ("CVE-2015-3306", 8.1, "High")
}


def scan_target(target):

    terminal_output = []
    results = []

    terminal_output.append(f"Starting scan on {target}...\n")

    try:
        socket.gethostbyname(target)
        terminal_output.append("Host is reachable\n")

    except:
        terminal_output.append("Host unreachable\n")
        return [], "\n".join(terminal_output)

    for port, service in common_ports.items():

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:

            if service in vulnerabilities:
                cve, cvss, risk = vulnerabilities[service]
            else:
                cve, cvss, risk = "N/A", "N/A", "Low"

            results.append({
                "Port": port,
                "Service": service,
                "CVE": cve,
                "CVSS": cvss,
                "Risk": risk
            })

            terminal_output.append(f"{port}/tcp   open   {service}")

        sock.close()

    terminal_output.append("\nScan Completed.")

    return results, "\n".join(terminal_output)