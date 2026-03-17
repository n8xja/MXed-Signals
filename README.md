# MXed-Signals
# V1.2.1 

Changes: 
V1.2.1
Updated README formatting.

V1.2 Resilience Updates

Added Query throttle

Added configuration feature to use environmental variables to set locations of domain list and log file

Added a retry if the previous runs returned a value, but the current run connects but does not return a value

DNS Record Monitor
Monitors SPF, DMARC, and MX records for domains and alerts on changes.

This python script takes a list of domains (default domains.txt) and loops through
the list and does the following:
- Retrieves the NS records
- Retrives the MX, SPF, DMARC records from each authoratitive DNS Server
- Compares the authoratitive DNS Server results and alerts on differences
- Compares the results on the previous run, and alerts if the current values does not match the last values

Dependencies:
pip install dnspython

# Configuration

Directory Configuration - Priority: Environment Variable > Script Variable > Current Directory

Environmental Variables:
- DNS_MONITOR_LOG_DIR - Where to store the logging output
- DNS_MONITOR_DOMAIN_DIR - Where to find the domain list

If the directories or files do not exist, they will be created.

# Email Configuration
- EMAIL_ENABLED = True  # Set to False to disable email alerts
- SMTP_SERVER = "127.0.0.1"  # Change to your SMTP server
- SMTP_PORT = 25  # Use 465 for SSL, 587 for TLS
- SMTP_USERNAME = ""  # Your email user id - empty setting means it does not use SMTP AUTH
- SMTP_PASSWORD = ""  # Your email app password
- EMAIL_FROM = "dnsmonitor@example.com"  # From address
- EMAIL_TO = ["dnsmonitor@example.com"]  # List of recipients
- EMAIL_SUBJECT_PREFIX = "[DNS Alert]"

# DNS Query Retry Configuration
- DNS_RETRY_ATTEMPTS = 3  # Number of retry attempts for failed DNS queries
- DNS_RETRY_DELAY = 2  # Delay in seconds between retry attempts
- DNS_EMPTY_RESPONSE_RETRIES = 3  # Number of retries when getting empty response but previous value existed
- DNS_QUERY_THROTTLE = 0.5  # Delay in seconds between DNS queries to avoid rate limiting

Note: DNS_EMPTY_RESPONSE_RETRIES
- this was added to slow down and be kind to smaller dns servers or when network conditions might be unfavorable.
- 0 = no delay


# Cron Example to Run every 15 minutes
Make sure the user can write to the directories

*/15 * * * * user DNS_MONITOR_LOG_DIR=/var/log/MXed-Signals DNS_MONITOR_DOMAIN_DIR=/etc/MXed-Signals /usr/bin/python3 /opt/dns_monitor.py
