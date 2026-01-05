import sys
import re

# ================= Constants ================

ALERT_THRESHOLD = 10

# syslog header validation
SYSLOG_PATTERN = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+"
    r"\d{2}:\d{2}:\d{2}\s+"
    r"\S+\s+"
    r"\S+:\s"
)

# IPv4 matcher
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# failed-auth indicators
FAILED_LOGIN_PATTERNS = (
    "authentication failure",
    "failed password",
    "invalid user",
    "check pass; user unknown",
    "authentication failed",
)

# ================ Main =================

def main():
    logfile = validate_arguments()

    total_lines = 0
    failed_logins_per_ip = {}

    with open(logfile, "r") as f:
        for line in f:
            total_lines += 1

            if not is_valid_syslog(line):
                continue

            if is_failed_login(line):
                ip = extract_ip(line)
                if ip:
                    failed_logins_per_ip[ip] = failed_logins_per_ip.get(ip, 0) + 1

    alerts = generate_alerts(failed_logins_per_ip)
    write_report(total_lines, failed_logins_per_ip, alerts)

    print("Analysis complete. Report written to report.txt")


# ================== Validation ==================

def validate_arguments():
    """
    validates length of command line arguments
    validates type of file
    checks if file exists
    if exists returns it
    """
    if len(sys.argv) != 2:
        print("Usage: python miniSIEM.py <logfile>")
        sys.exit(1)

    logfile = sys.argv[1]

    if not logfile.endswith((".log", ".txt")):
        print("Invalid file format. Expected .log or .txt")
        sys.exit(1)

    try:
        open(logfile, "r").close()
    except FileNotFoundError:
        print(f"File not found: {logfile}")
        sys.exit(1)

    return logfile


def is_valid_syslog(line) -> bool:
    """
    Validates line using SYSLOG_PATTERN
    return Bool
    """
    return bool(SYSLOG_PATTERN.match(line))


def is_valid_ipv4(ip) -> bool:
    """
    Checks if IP is valid
    returns Bool
    """
    parts = ip.split(".")
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
    return True



# ==================Detection Logic ==================

def is_failed_login(line) -> bool:
    """
    checks if line is a pattern in FAILED_LOGIN_PATTERNS
    returns the pattern
    """
    lower_line = line.lower()
    return any(pattern in lower_line for pattern in FAILED_LOGIN_PATTERNS)


def extract_ip(line):
    """
    extracts IP using IP_PATTERN
    returns IP if exists else returns None
    """
    match = IP_PATTERN.search(line)
    if not match:
        return None

    ip = match.group(0)
    return ip if is_valid_ipv4(ip) else None



# ================== Alerting ==================

def generate_alerts(failed_logins_per_ip) -> list:
    """
    checks if failed logins for a specific IP is greater than the ALERT_THRESHOLD
    if yes adds the count and the ip to  the alerts list
    """
    alerts = []
    for ip, count in failed_logins_per_ip.items():
        if count >= ALERT_THRESHOLD:
            alerts.append(f"ALERT: {count} failed login attempts from {ip}")
    return alerts


# ================== Reporting ==================

def write_report(total_lines, failed_logins_per_ip, alerts) -> None:
    """
    opens a report file
    writes in it:
    Total log lines processed
    Failed login attempts per IP
    Alerts triggered
    """
    with open("report.txt", "w") as report:
        report.write(f"Total log lines processed: {total_lines}\n\n")

        report.write("Failed login attempts per IP:\n")
        for ip, count in sorted(failed_logins_per_ip.items(), key=lambda x: x[1], reverse=True):
            report.write(f"{ip}: {count}\n")

        report.write("\nAlerts:\n")
        if alerts:
            for alert in alerts:
                report.write(f"{alert}\n")
        else:
            report.write("No alerts triggered.\n")


if __name__ == "__main__":
    main()
