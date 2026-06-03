"""
Utility functions for the MAD-CTI application
"""

import os
import csv
import random
from datetime import datetime, timedelta
from models import ThreatRecord, DataUpload, User

ALLOWED_EXTENSIONS = {'csv'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_sample_csv(num_records=200):
    """Generate sample CSV file with threat data"""
    
    # Sample threat texts
    hack_samples = [
        "Unauthorized access detected on server 192.168.1.100. Brute force attack on SSH port.",
        "Phishing campaign targeting employees via email. Credential harvesting attempt.",
        "SQL injection vulnerability exploited on web application. Database breach confirmed.",
        "DDoS attack from botnet targeting api.example.com. Traffic spike detected.",
        "Backdoor installed via compromised admin credentials. Lateral movement observed.",
    ]
    
    malware_samples = [
        "Ransomware infection detected. WannaCry variant encrypting files on network shares.",
        "Trojan horse discovered in email attachment. Keylogger functionality identified.",
        "Spyware installation via drive-by download. Data exfiltration to evil.com detected.",
        "Emotet malware spreading through network. Botnet communication observed.",
        "Cryptominer malware consuming CPU resources. Monero mining activity detected.",
    ]
    
    vulnerability_samples = [
        "CVE-2021-44228 Log4Shell vulnerability discovered in production systems.",
        "Buffer overflow vulnerability in legacy application. Remote code execution possible.",
        "XSS vulnerability found in user input validation. Session hijacking risk.",
        "Unpatched Apache Struts vulnerability CVE-2017-5638. Exploitation attempts detected.",
        "CSRF vulnerability in web application. Unauthorized actions possible.",
    ]
    
    # IOCs to include
    ips = ['192.168.1.100', '10.0.0.50', '172.16.0.1', '203.0.113.42', '198.51.100.23']
    domains = ['evil.com', 'malware.net', 'phishing-site.org', 'c2-server.xyz', 'badactor.io']
    hashes = [
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        '5d41402abc4b2a76b9719d911017c592',
        'adc83b19e793491b1c6ea0fd8b46cd9f32e592fc'
    ]
    cves = ['CVE-2021-44228', 'CVE-2017-5638', 'CVE-2019-0708', 'CVE-2020-1472']
    
    # Generate records
    filepath = os.path.join('uploads', 'sample_threat_data.csv')
    os.makedirs('uploads', exist_ok=True)
    
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = [
            'id', 'timestamp', 'source', 'text', 'url', 'ip_address', 
            'domain', 'hash', 'cve', 'severity', 'category'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for i in range(num_records):
            # Randomly select category
            category = random.choice(['hack', 'malware', 'vulnerability'])
            
            if category == 'hack':
                text = random.choice(hack_samples)
            elif category == 'malware':
                text = random.choice(malware_samples)
            else:
                text = random.choice(vulnerability_samples)
            
            # Add random IOCs to text
            if random.random() > 0.5:
                text += f" IP: {random.choice(ips)}"
            if random.random() > 0.5:
                text += f" Domain: {random.choice(domains)}"
            if random.random() > 0.7 and category == 'vulnerability':
                text += f" {random.choice(cves)}"
            
            # Generate timestamp
            timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
            
            row = {
                'id': i + 1,
                'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'source': random.choice(['darkweb', 'osint', 'honeypot', 'ids', 'siem']),
                'text': text,
                'url': f"https://{random.choice(domains)}/thread/{random.randint(1000, 9999)}",
                'ip_address': random.choice(ips) if random.random() > 0.5 else '',
                'domain': random.choice(domains) if random.random() > 0.5 else '',
                'hash': random.choice(hashes) if random.random() > 0.7 else '',
                'cve': random.choice(cves) if category == 'vulnerability' and random.random() > 0.5 else '',
                'severity': random.choice(['low', 'medium', 'high', 'critical']),
                'category': category
            }
            
            writer.writerow(row)
    
    return filepath


def get_analytics_data():
    """Get analytics data for dashboard visualizations"""
    
    # Get all threat records
    threats = ThreatRecord.query.all()
    
    if not threats:
        return {
            'threat_timeline': [],
            'threat_distribution': {},
            'severity_distribution': {},
            'top_keywords': [],
            'ioc_statistics': {}
        }
    
    # Threat distribution
    threat_distribution = {
        'hack': sum(1 for t in threats if t.threat_type == 'hack'),
        'malware': sum(1 for t in threats if t.threat_type == 'malware'),
        'vulnerability': sum(1 for t in threats if t.threat_type == 'vulnerability')
    }
    
    # Severity distribution
    severity_distribution = {
        'critical': sum(1 for t in threats if t.severity_level == 'critical'),
        'high': sum(1 for t in threats if t.severity_level == 'high'),
        'medium': sum(1 for t in threats if t.severity_level == 'medium'),
        'low': sum(1 for t in threats if t.severity_level == 'low')
    }
    
    # Timeline data (last 30 days)
    timeline = {}
    for threat in threats:
        if threat.processed_at:
            date_key = threat.processed_at.strftime('%Y-%m-%d')
            if date_key not in timeline:
                timeline[date_key] = {'hack': 0, 'malware': 0, 'vulnerability': 0}
            timeline[date_key][threat.threat_type] += 1
    
    threat_timeline = [
        {
            'date': date,
            'hack': counts['hack'],
            'malware': counts['malware'],
            'vulnerability': counts['vulnerability']
        }
        for date, counts in sorted(timeline.items())
    ]
    
    # Top keywords
    keyword_counts = {}
    for threat in threats:
        keywords = threat.get_keywords()
        for keyword in keywords:
            keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
    
    top_keywords = [
        {'keyword': k, 'count': v}
        for k, v in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True)[:20]
    ]
    
    # IOC statistics
    total_ips = 0
    total_domains = 0
    total_hashes = 0
    total_cves = 0
    
    for threat in threats:
        iocs = threat.get_ioc_data()
        total_ips += len(iocs.get('ipv4', []))
        total_domains += len(iocs.get('domain', []))
        total_hashes += len(iocs.get('md5', [])) + len(iocs.get('sha1', [])) + len(iocs.get('sha256', []))
        total_cves += len(iocs.get('cve', []))
    
    ioc_statistics = {
        'ip_addresses': total_ips,
        'domains': total_domains,
        'file_hashes': total_hashes,
        'cves': total_cves
    }
    
    # User activity
    users = User.query.all()
    user_activity = [
        {
            'username': user.username,
            'uploads': len(user.uploads),
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M') if user.last_login else 'Never'
        }
        for user in users
    ]
    
    return {
        'threat_timeline': threat_timeline,
        'threat_distribution': threat_distribution,
        'severity_distribution': severity_distribution,
        'top_keywords': top_keywords,
        'ioc_statistics': ioc_statistics,
        'user_activity': user_activity,
        'total_threats': len(threats)
    }


def format_timestamp(timestamp):
    """Format timestamp for display"""
    if not timestamp:
        return 'N/A'
    return timestamp.strftime('%Y-%m-%d %H:%M:%S')


def format_file_size(size_bytes):
    """Format file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
