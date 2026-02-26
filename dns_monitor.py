#!/usr/bin/env python3
"""
DNS Record Monitor
Monitors SPF, DMARC, and MX records for domains and alerts on changes.
"""

import dns.resolver
import dns.query
import dns.message
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
import sys
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Configuration
# Where to store the project files
PARENT_DIR=""

# The DNS server to retrieve the NS Records
DNS_SERVER = "8.8.8.8"

# Where to find the list of domains to monitor
DOMAINS_FILE = PARENT_DIR + "domains.txt"

# Where to store DNS Values for later comparision
STORAGE_FILE = PARENT_DIR + "dns_records.json"

# Where to store the results of each run
LOG_FILE = PARENT_DIR + "dns_monitor.log"

# Where to store the detected changes
ALERT_LOG_FILE = PARENT_DIR + "dns_alerts.log"

# Email Configuration

# Set to False to disable email alerts
EMAIL_ENABLED = True  

SMTP_SERVER = "127.0.0.1 " 

# Use 465 for SSL, 587 for TLS
SMTP_PORT = 25  

# Your email address - empty setting means it does not use SMTP AUTH
SMTP_USERNAME = ""  

# Your email password or app password
SMTP_PASSWORD = ""  

# From address for the alert
EMAIL_FROM = "dnsmonitor@example.com"  # From address

# Where to send the alerts
EMAIL_TO = ["dnsmonitor@example.com", "noc@example.com"]  

# Email Alert Subject line Prefix
EMAIL_SUBJECT_PREFIX = "[DNS Alert]"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Setup separate alert logger
alert_logger = logging.getLogger('alerts')
alert_logger.setLevel(logging.WARNING)
alert_handler = logging.FileHandler(ALERT_LOG_FILE)
alert_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
alert_logger.addHandler(alert_handler)


class DNSMonitor:
    def __init__(self, dns_server: str = DNS_SERVER):
        self.dns_server = dns_server
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [dns_server]
        
    def get_authoritative_nameservers(self, domain: str) -> List[str]:
        """Query for authoritative nameservers of a domain."""
        try:
            ns_records = self.resolver.resolve(domain, 'NS')
            nameservers = [str(ns.target).rstrip('.') for ns in ns_records]
            logger.info(f"Found authoritative nameservers for {domain}: {nameservers}")
            return nameservers
        except Exception as e:
            logger.error(f"Error getting NS records for {domain}: {e}")
            return []
    
    def query_authoritative_server(self, domain: str, record_type: str, 
                                   nameserver: str) -> List[str]:
        """Query a specific authoritative nameserver for records."""
        try:
            # Resolve the nameserver IP if needed
            ns_resolver = dns.resolver.Resolver()
            ns_resolver.nameservers = [self.dns_server]
            ns_ip = str(ns_resolver.resolve(nameserver, 'A')[0])
            
            # Create and send query to authoritative server
            query = dns.message.make_query(domain, record_type)
            
            # Try UDP first
            try:
                response = dns.query.udp(query, ns_ip, timeout=10)
                
                # Check if response was truncated (TC flag set)
                if response.flags & dns.flags.TC:
                    logger.info(f"Response truncated for {domain} {record_type}, switching to TCP")
                    # Retry with TCP
                    response = dns.query.tcp(query, ns_ip, timeout=10)
                    logger.info(f"Successfully retrieved {domain} {record_type} via TCP")
                    
            except Exception as udp_error:
                # If UDP fails for any reason, try TCP as fallback
                logger.info(f"UDP query failed for {domain} {record_type}, attempting TCP: {udp_error}")
                response = dns.query.tcp(query, ns_ip, timeout=10)
                logger.info(f"Successfully retrieved {domain} {record_type} via TCP")
            
            records = []
            for answer in response.answer:
                for item in answer:
                    records.append(str(item))
            
            return records
        except Exception as e:
            logger.warning(f"Error querying {nameserver} for {domain} {record_type}: {e}")
            return []
    
    def get_spf_record(self, domain: str, nameserver: str) -> Optional[str]:
        """Get SPF record from authoritative nameserver."""
        try:
            txt_records = self.query_authoritative_server(domain, 'TXT', nameserver)
            for record in txt_records:
                record_clean = record.strip('"')
                if record_clean.startswith('v=spf1'):
                    logger.info(f"SPF record for {domain}: {record_clean}")
                    return record_clean
            logger.info(f"No SPF record found for {domain}")
            return None
        except Exception as e:
            logger.error(f"Error getting SPF for {domain}: {e}")
            return None
    
    def get_dmarc_record(self, domain: str, nameserver: str) -> Optional[str]:
        """Get DMARC record from authoritative nameserver."""
        dmarc_domain = f"_dmarc.{domain}"
        try:
            txt_records = self.query_authoritative_server(dmarc_domain, 'TXT', nameserver)
            for record in txt_records:
                record_clean = record.strip('"')
                if record_clean.startswith('v=DMARC1'):
                    logger.info(f"DMARC record for {domain}: {record_clean}")
                    return record_clean
            logger.info(f"No DMARC record found for {domain}")
            return None
        except Exception as e:
            logger.error(f"Error getting DMARC for {domain}: {e}")
            return None
    
    def get_mx_records(self, domain: str, nameserver: str) -> List[str]:
        """Get MX records from authoritative nameserver."""
        try:
            mx_records = self.query_authoritative_server(domain, 'MX', nameserver)
            mx_list = sorted([str(mx) for mx in mx_records])
            logger.info(f"MX records for {domain}: {mx_list}")
            return mx_list
        except Exception as e:
            logger.error(f"Error getting MX for {domain}: {e}")
            return []
    
    def get_all_records(self, domain: str) -> Dict:
        """Get all DNS records for a domain from all authoritative nameservers."""
        logger.info(f"\n{'='*60}")
        logger.info(f"Processing domain: {domain}")
        logger.info(f"{'='*60}")
        
        # Get authoritative nameservers
        nameservers = self.get_authoritative_nameservers(domain)
        if not nameservers:
            logger.error(f"Could not find authoritative nameservers for {domain}")
            return {
                'domain': domain,
                'timestamp': datetime.now().isoformat(),
                'error': 'No authoritative nameservers found'
            }
        
        # Query all authoritative nameservers
        all_ns_records = {}
        for nameserver in nameservers:
            logger.info(f"Querying authoritative nameserver: {nameserver}")
            
            spf = self.get_spf_record(domain, nameserver)
            dmarc = self.get_dmarc_record(domain, nameserver)
            mx = self.get_mx_records(domain, nameserver)
            
            all_ns_records[nameserver] = {
                'spf': spf,
                'dmarc': dmarc,
                'mx': mx
            }
        
        # Check for inconsistencies across nameservers
        inconsistencies = self.check_nameserver_consistency(domain, all_ns_records)
        
        # Use the first nameserver's records as the canonical record
        # (or you could implement logic to choose the most common response)
        first_ns = nameservers[0]
        canonical_records = all_ns_records[first_ns]
        
        return {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'nameservers': nameservers,
            'spf': canonical_records['spf'],
            'dmarc': canonical_records['dmarc'],
            'mx': canonical_records['mx'],
            'all_nameserver_records': all_ns_records,
            'inconsistencies': inconsistencies
        }
    
    def check_nameserver_consistency(self, domain: str, all_ns_records: Dict) -> Dict:
        """Check if all nameservers return the same records."""
        inconsistencies = {
            'spf_inconsistent': False,
            'dmarc_inconsistent': False,
            'mx_inconsistent': False,
            'details': []
        }
        
        if len(all_ns_records) <= 1:
            return inconsistencies
        
        # Get all unique values for each record type
        spf_values = set()
        dmarc_values = set()
        mx_values = set()
        
        for ns, records in all_ns_records.items():
            spf_values.add(records.get('spf'))
            dmarc_values.add(records.get('dmarc'))
            # Convert MX list to tuple for set comparison
            mx_tuple = tuple(sorted(records.get('mx', [])))
            mx_values.add(mx_tuple)
        
        # Check SPF consistency
        if len(spf_values) > 1:
            inconsistencies['spf_inconsistent'] = True
            detail = f"SPF records differ across nameservers:"
            for ns, records in all_ns_records.items():
                detail += f"\n  {ns}: {records.get('spf')}"
            inconsistencies['details'].append(detail)
            logger.warning(detail)
            alert_logger.warning(detail)
        
        # Check DMARC consistency
        if len(dmarc_values) > 1:
            inconsistencies['dmarc_inconsistent'] = True
            detail = f"DMARC records differ across nameservers:"
            for ns, records in all_ns_records.items():
                detail += f"\n  {ns}: {records.get('dmarc')}"
            inconsistencies['details'].append(detail)
            logger.warning(detail)
            alert_logger.warning(detail)
        
        # Check MX consistency
        if len(mx_values) > 1:
            inconsistencies['mx_inconsistent'] = True
            detail = f"MX records differ across nameservers:"
            for ns, records in all_ns_records.items():
                detail += f"\n  {ns}: {records.get('mx')}"
            inconsistencies['details'].append(detail)
            logger.warning(detail)
            alert_logger.warning(detail)
        
        return inconsistencies


class RecordStorage:
    def __init__(self, storage_file: str = STORAGE_FILE):
        self.storage_file = Path(storage_file)
        self.data = self._load()
    
    def _load(self) -> Dict:
        """Load existing records from storage."""
        if self.storage_file.exists():
            try:
                with open(self.storage_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading storage file: {e}")
                return {}
        return {}
    
    def save(self):
        """Save records to storage."""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(self.data, f, indent=2)
            logger.info(f"Saved records to {self.storage_file}")
        except Exception as e:
            logger.error(f"Error saving storage file: {e}")
    
    def get_previous(self, domain: str) -> Optional[Dict]:
        """Get previous records for a domain."""
        return self.data.get(domain)
    
    def update(self, domain: str, records: Dict):
        """Update records for a domain."""
        self.data[domain] = records
    
    def compare_records(self, domain: str, current: Dict, previous: Dict) -> Dict[str, bool]:
        """Compare current and previous records, return what changed."""
        changes = {
            'spf_changed': current.get('spf') != previous.get('spf'),
            'dmarc_changed': current.get('dmarc') != previous.get('dmarc'),
            'mx_changed': current.get('mx') != previous.get('mx')
        }
        return changes


def load_domains(filename: str) -> List[str]:
    """Load domain list from file."""
    try:
        with open(filename, 'r') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(domains)} domains from {filename}")
        return domains
    except FileNotFoundError:
        logger.error(f"Domain file {filename} not found!")
        return []
    except Exception as e:
        logger.error(f"Error loading domains: {e}")
        return []


def send_email_alert(domain: str, changes: Dict[str, bool], current: Dict, previous: Dict, inconsistencies: Dict = None):
    """Send email alert for DNS record changes."""
    if not EMAIL_ENABLED:
        return
    
    try:
        # Determine if this is a change alert or inconsistency alert
        has_changes = any(changes.values())
        has_inconsistencies = inconsistencies and any([
            inconsistencies.get('spf_inconsistent'),
            inconsistencies.get('dmarc_inconsistent'),
            inconsistencies.get('mx_inconsistent')
        ])
        
        if not has_changes and not has_inconsistencies:
            return
        
        # Create email content
        subject_parts = []
        if has_changes:
            subject_parts.append("DNS Changes")
        if has_inconsistencies:
            subject_parts.append("Nameserver Inconsistencies")
        
        subject = f"{EMAIL_SUBJECT_PREFIX} {' & '.join(subject_parts)} for {domain}"
        
        # Build HTML email body
        html_body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                .header {{ background-color: #ff6b6b; color: white; padding: 15px; }}
                .inconsistency-header {{ background-color: #ffa500; color: white; padding: 15px; }}
                .content {{ padding: 20px; }}
                .record-change {{ margin: 15px 0; padding: 10px; background-color: #f8f9fa; border-left: 4px solid #ff6b6b; }}
                .inconsistency {{ margin: 15px 0; padding: 10px; background-color: #fff3cd; border-left: 4px solid #ffa500; }}
                .record-type {{ font-weight: bold; color: #495057; }}
                .previous {{ color: #dc3545; }}
                .current {{ color: #28a745; }}
                .nameserver {{ font-family: monospace; font-size: 12px; margin: 5px 0; }}
                .footer {{ margin-top: 30px; padding: 15px; background-color: #f8f9fa; font-size: 12px; color: #6c757d; }}
            </style>
        </head>
        <body>
        """
        
        # Add inconsistency section if present
        if has_inconsistencies:
            html_body += f"""
            <div class="inconsistency-header">
                <h2>⚠️ Nameserver Inconsistency Alert</h2>
            </div>
            <div class="content">
                <p><strong>Domain:</strong> {domain}</p>
                <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <p style="color: #856404;"><strong>WARNING:</strong> Not all authoritative nameservers are returning the same records!</p>
                <hr>
            """
            
            for detail in inconsistencies.get('details', []):
                lines = detail.split('\n')
                html_body += f"""
                <div class="inconsistency">
                    <div class="record-type">{lines[0]}</div>
                """
                for line in lines[1:]:
                    html_body += f'<div class="nameserver">{line}</div>'
                html_body += "</div>"
            
            html_body += "</div>"
        
        # Add changes section if present
        if has_changes:
            if has_inconsistencies:
                html_body += '<div class="header"><h2>DNS Record Changes</h2></div>'
            else:
                html_body += '<div class="header"><h2>DNS Record Change Alert</h2></div>'
            
            html_body += f"""
            <div class="content">
                <p><strong>Domain:</strong> {domain}</p>
                <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
                <hr>
            """
            
            # Add SPF changes
            if changes['spf_changed']:
                html_body += f"""
                    <div class="record-change">
                        <div class="record-type">SPF Record Changed</div>
                        <p class="previous"><strong>Previous:</strong> {previous.get('spf') or 'None'}</p>
                        <p class="current"><strong>Current:</strong> {current.get('spf') or 'None'}</p>
                    </div>
                """
            
            # Add DMARC changes
            if changes['dmarc_changed']:
                html_body += f"""
                    <div class="record-change">
                        <div class="record-type">DMARC Record Changed</div>
                        <p class="previous"><strong>Previous:</strong> {previous.get('dmarc') or 'None'}</p>
                        <p class="current"><strong>Current:</strong> {current.get('dmarc') or 'None'}</p>
                    </div>
                """
            
            # Add MX changes
            if changes['mx_changed']:
                prev_mx = '<br>'.join(previous.get('mx', [])) or 'None'
                curr_mx = '<br>'.join(current.get('mx', [])) or 'None'
                html_body += f"""
                    <div class="record-change">
                        <div class="record-type">MX Records Changed</div>
                        <p class="previous"><strong>Previous:</strong><br>{prev_mx}</p>
                        <p class="current"><strong>Current:</strong><br>{curr_mx}</p>
                    </div>
                """
            
            html_body += "</div>"
        
        html_body += """
            <div class="footer">
                <p>This is an automated alert from DNS Monitor.</p>
                <p>Please review these changes to ensure they are authorized.</p>
            </div>
        </body>
        </html>
        """
        
        # Create plain text version
        text_body = ""
        
        if has_inconsistencies:
            text_body += f"""NAMESERVER INCONSISTENCY ALERT

Domain: {domain}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

WARNING: Not all authoritative nameservers are returning the same records!

"""
            for detail in inconsistencies.get('details', []):
                text_body += detail + "\n\n"
        
        if has_changes:
            if has_inconsistencies:
                text_body += "\n" + "="*60 + "\n\n"
            
            text_body += f"""DNS Record Change Alert

Domain: {domain}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}

"""
            
            if changes['spf_changed']:
                text_body += f"""SPF Record Changed:
Previous: {previous.get('spf') or 'None'}
Current:  {current.get('spf') or 'None'}

"""
            
            if changes['dmarc_changed']:
                text_body += f"""DMARC Record Changed:
Previous: {previous.get('dmarc') or 'None'}
Current:  {current.get('dmarc') or 'None'}

"""
            
            if changes['mx_changed']:
                text_body += f"""MX Records Changed:
Previous: {', '.join(previous.get('mx', [])) or 'None'}
Current:  {', '.join(current.get('mx', [])) or 'None'}

"""
        
        text_body += """
This is an automated alert from DNS Monitor.
Please review these changes to ensure they are authorized.
"""
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = EMAIL_FROM
        msg['To'] = ', '.join(EMAIL_TO)
        
        # Attach both plain text and HTML versions
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        # Send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            # Only use STARTTLS if not using port 25 (plain SMTP)
            if SMTP_PORT != 25:
                server.starttls()
            
            # Only authenticate if username is configured
            if SMTP_USERNAME != "":
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            
            server.send_message(msg)
        
        logger.info(f"Email alert sent for {domain} to {', '.join(EMAIL_TO)}")
        alert_logger.info(f"Email alert sent for {domain} to {', '.join(EMAIL_TO)}")
        
    except Exception as e:
        logger.error(f"Failed to send email alert for {domain}: {e}")
        alert_logger.error(f"Failed to send email alert for {domain}: {e}")


def alert_changes(domain: str, changes: Dict[str, bool], current: Dict, previous: Dict):
    """Alert on record changes."""
    has_changes = any(changes.values())
    inconsistencies = current.get('inconsistencies', {})
    has_inconsistencies = any([
        inconsistencies.get('spf_inconsistent'),
        inconsistencies.get('dmarc_inconsistent'),
        inconsistencies.get('mx_inconsistent')
    ])
    
    if not has_changes and not has_inconsistencies:
        return
    
    # Log changes to alert log
    if has_changes:
        alert_msg = []
        alert_msg.append(f"\n{'!'*60}")
        alert_msg.append(f"ALERT: Changes detected for {domain}")
        alert_msg.append(f"{'!'*60}")
        
        if changes['spf_changed']:
            alert_msg.append(f"SPF CHANGED:")
            alert_msg.append(f"  Previous: {previous.get('spf')}")
            alert_msg.append(f"  Current:  {current.get('spf')}")
        
        if changes['dmarc_changed']:
            alert_msg.append(f"DMARC CHANGED:")
            alert_msg.append(f"  Previous: {previous.get('dmarc')}")
            alert_msg.append(f"  Current:  {current.get('dmarc')}")
        
        if changes['mx_changed']:
            alert_msg.append(f"MX CHANGED:")
            alert_msg.append(f"  Previous: {previous.get('mx')}")
            alert_msg.append(f"  Current:  {current.get('mx')}")
        
        alert_msg.append(f"{'!'*60}\n")
        
        full_alert = '\n'.join(alert_msg)
        logger.warning(full_alert)
        alert_logger.warning(full_alert)
    
    # Log inconsistencies
    if has_inconsistencies:
        alert_msg = []
        alert_msg.append(f"\n{'!'*60}")
        alert_msg.append(f"ALERT: Nameserver inconsistencies detected for {domain}")
        alert_msg.append(f"{'!'*60}")
        
        for detail in inconsistencies.get('details', []):
            alert_msg.append(detail)
        
        alert_msg.append(f"{'!'*60}\n")
        
        full_alert = '\n'.join(alert_msg)
        logger.warning(full_alert)
        alert_logger.warning(full_alert)
    
    # Send email alert (handles both changes and inconsistencies)
    send_email_alert(domain, changes, current, previous, inconsistencies)


def main():
    """Main execution function."""
    logger.info(f"\n{'#'*60}")
    logger.info(f"DNS Monitor Started - {datetime.now().isoformat()}")
    logger.info(f"{'#'*60}\n")
    
    # Load domains
    domains = load_domains(DOMAINS_FILE)
    if not domains:
        logger.error("No domains to process. Exiting.")
        return
    
    # Initialize
    monitor = DNSMonitor(DNS_SERVER)
    storage = RecordStorage(STORAGE_FILE)
    
    # Process each domain
    for domain in domains:
        try:
            # Get current records
            current_records = monitor.get_all_records(domain)
            
            # Skip if there was an error
            if 'error' in current_records:
                continue
            
            # Get previous records
            previous_records = storage.get_previous(domain)
            
            # Check for changes
            if previous_records:
                changes = storage.compare_records(domain, current_records, previous_records)
                alert_changes(domain, changes, current_records, previous_records)
            else:
                logger.info(f"First time monitoring {domain} - no previous records to compare")
            
            # Update storage
            storage.update(domain, current_records)
            
        except Exception as e:
            logger.error(f"Error processing {domain}: {e}")
            continue
    
    # Save all records
    storage.save()
    
    logger.info(f"\n{'#'*60}")
    logger.info(f"DNS Monitor Completed - {datetime.now().isoformat()}")
    logger.info(f"{'#'*60}\n")


if __name__ == "__main__":
    main()
