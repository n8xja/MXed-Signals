# MXed-Signals
# V1.0 - Tony Schliesser tony.schliesser@gmail.com

Email DNS monitoring and alerting tool.

This python script takes a list of domains (default domains.txt) and loops through
the list and does the following:
- Retrieves the NS records
- Retrives the MX, SPF, DMARC records from each authoratitive DNS Server
- Compares the authoratitive DNS Server results and alerts on differences
- Compares the results on the previous run, and alerts if the current values does not match the last values

Script Configuration:
# Configuration
# Where to store the project files
PARENT_DIR="/var/log/MXed-Signals/"

# This is the initial server to learn the NS records.
DNS_SERVER = "8.8.8.8" 

# The list of domains to monitor
DOMAINS_FILE = PARENT_DIR + "domains.txt"

# Where to store DNS values - for the comparison
STORAGE_FILE = PARENT_DIR + "dns_records.json" 

# Where to store the files results of each run
LOG_FILE = PARENT_DIR + "dns_monitor.log" 

# Seperate log file of alerts sent
ALERT_LOG_FILE = PARENT_DIR + "dns_alerts.log"


# Email Configuration

EMAIL_ENABLED = True  # Set to False to disable email alerts

SMTP_SERVER = "127.0.0.1"  # Change to your SMTP server

SMTP_PORT = 25  # Use 465 for SSL, 587 for TLS

SMTP_USERNAME = ""  # Your email user id - empty setting means it does not use SMTP AUTH

SMTP_PASSWORD = ""  # Your email app password

EMAIL_FROM = "dnsmonitor@example.com"  # From address

EMAIL_TO = ["dnsmonitor@example.com"]  # List of recipients

EMAIL_SUBJECT_PREFIX = "[DNS Alert]"


