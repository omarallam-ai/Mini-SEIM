
# MiniSEIM

#### Video Demo: https://youtu.be/aU1EabMYwqY

#### Description:
MiniSEIM is a Python-based log analysis tool designed to parse and analyze Linux system log files. Its primary purpose is to assist users, especially those interested in cybersecurity, in quickly identifying patterns of failed login attempts and potential security alerts. The program reads a given Linux log file, validates its format, and generates a comprehensive report in a text file named `report.txt`.

The generated report contains the following key information:
- **Total log lines processed** – a count of all lines read from the log file.
- **Failed login attempts per IP** – a dictionary-like summary showing which IP addresses have had authentication failures and how many times each.
- **Alerts triggered** – notifications for IP addresses exceeding a configurable threshold of failed login attempts, helping security analysts detect suspicious activity.

This project was designed to not only strengthen Python programming skills but also to provide hands-on experience with cybersecurity monitoring concepts, including log analysis and alert generation.

---

#### How It Works / Key Functions:
MiniSEIM is built around several core Python functions that work together to perform its analysis:

1. **`validate_arguments()`** – Ensures the user provides a valid log file as a command-line argument. The function checks that the file exists and has the correct `.log` or `.txt` format. If validation fails, the program exits gracefully with an error message.

2. **`is_valid_syslog(line)`** – Uses a regular expression to determine whether a line in the log file conforms to a standard syslog format. Lines that do not match this format are ignored, ensuring only valid log entries are processed.

3. **`is_failed_login(line)`** – Checks each log line for indicators of failed authentication, such as “authentication failure,” “failed password,” or “invalid user.”

4. **`extract_ip(line)`** – Extracts the IP address associated with a failed login attempt using an IPv4 pattern matcher.

5. **`generate_alerts(failed_logins_per_ip)`** – Compares the number of failed logins per IP against a threshold (`ALERT_THRESHOLD = 10`). IPs exceeding this limit are flagged as alerts.

6. **`write_report(total_lines, failed_logins_per_ip, alerts)`** – Creates or overwrites `report.txt` with a structured summary of the analysis results.

The program is modular, making it easy to extend in the future. For example, support for JSON or Windows log formats could be added by implementing additional validation and extraction functions.

---

#### How to Run:
To use MiniSEIM, run the program from the command line, passing the log file as an argument:

```bash
python project.py <logfile>
