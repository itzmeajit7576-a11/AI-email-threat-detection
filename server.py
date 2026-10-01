"""
Inbox Guardian - Backend API & Static Web Server
Built using Python 3 standard library (no third-party dependencies required).
Provides REST API endpoints for email threat analysis, threat intelligence,
IP geolocation telemetry, and forensic report generation.
"""

import http.server
import socketserver
import json
import re
import os
import email
from email import policy
import hashlib
from datetime import datetime, timezone

PORT = 8000
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def calculate_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8', errors='ignore')).hexdigest()

def mock_ip_lookup(ip: str):
    # Simulated geo and ASN intelligence for demonstration
    ip_database = {
        "185.220.101.45": {
            "ip": "185.220.101.45",
            "country": "Romania",
            "country_code": "RO",
            "city": "Bucharest",
            "region": "Ilfov",
            "latitude": 44.4268,
            "longitude": 26.1025,
            "isp": "M247 Europe Ltd",
            "asn": "AS200052",
            "organization": "Known Tor Exit / Bulletproof Hosting Relay",
            "risk_score": 89,
            "reputation": "Malicious",
            "abuse_reports": 142
        },
        "198.51.100.24": {
            "ip": "198.51.100.24",
            "country": "Germany",
            "country_code": "DE",
            "city": "Frankfurt am Main",
            "region": "Hesse",
            "latitude": 50.1109,
            "longitude": 8.6821,
            "isp": "Equinix Frankfurt Data Center",
            "asn": "AS8075",
            "organization": "Intermediate SMTP Relay Cluster",
            "risk_score": 45,
            "reputation": "Suspicious",
            "abuse_reports": 18
        },
        "104.244.42.1": {
            "ip": "104.244.42.1",
            "country": "United States",
            "country_code": "US",
            "city": "Ashburn",
            "region": "Virginia",
            "latitude": 39.0438,
            "longitude": -77.4874,
            "isp": "Cloudflare Ingress Protection",
            "asn": "AS13335",
            "organization": "Cloudflare Secure Edge Gateway",
            "risk_score": 8,
            "reputation": "Clean / Enterprise Gateway",
            "abuse_reports": 0
        },
        "194.26.29.112": {
            "ip": "194.26.29.112",
            "country": "Russia",
            "country_code": "RU",
            "city": "Saint Petersburg",
            "region": "Northwestern",
            "latitude": 59.9343,
            "longitude": 30.3351,
            "isp": "Selectel Network Infrastructure",
            "asn": "AS49505",
            "organization": "Direct-to-IP Phishing C2 Host",
            "risk_score": 96,
            "reputation": "Critical Threat",
            "abuse_reports": 310
        }
    }
    
    if ip in ip_database:
        return ip_database[ip]
    
    # Generic realistic fallback for any other IP
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    lats = [37.7749, 51.5074, 35.6762, 48.8566, -33.8688, 1.3521, 28.6139]
    longs = [-122.4194, -0.1278, 139.6503, 2.3522, 151.2093, 103.8198, 77.2090]
    countries = ["United States", "United Kingdom", "Japan", "France", "Australia", "Singapore", "India"]
    codes = ["US", "GB", "JP", "FR", "AU", "SG", "IN"]
    idx = h % len(lats)
    
    return {
        "ip": ip,
        "country": countries[idx],
        "country_code": codes[idx],
        "city": "Telemetry Center",
        "region": "Global Relay",
        "latitude": lats[idx],
        "longitude": longs[idx],
        "isp": f"Simulated BGP Peer AS{10000 + (h % 50000)}",
        "asn": f"AS{10000 + (h % 50000)}",
        "organization": "Internet Transit Provider (Simulated)",
        "risk_score": (h % 80) + 10,
        "reputation": "Monitored",
        "abuse_reports": h % 25
    }

class InboxGuardianHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/'):
            self.handle_api_get()
        else:
            super().do_GET()

    def do_POST(self):
        if self.path.startswith('/api/'):
            self.handle_api_post()
        else:
            self.send_error(404, "Endpoint not found")

    def send_json(self, data, status_code=200):
        response_bytes = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Length', str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def handle_api_get(self):
        path = self.path.split('?')[0]
        
        # System Health Status
        if path == '/api/status':
            self.send_json({
                "status": "OPERATIONAL",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "services": {
                    "ai_engine": {"status": "ONLINE", "latency_ms": 12, "version": "v4.2.1-heuristic"},
                    "header_parser": {"status": "ONLINE", "latency_ms": 4, "rfc_standard": "RFC 5322 / RFC 2045"},
                    "threat_intelligence": {"status": "ONLINE", "latency_ms": 19, "active_feeds": 8},
                    "geolocation_engine": {"status": "ONLINE", "latency_ms": 15, "database": "BGP-GeoIP-Simulated"},
                    "report_generator": {"status": "ONLINE", "latency_ms": 8, "formats": ["JSON", "PDF", "STIX-2.1"]}
                },
                "uptime": "99.98%"
            })
            return

        # Threat Intelligence Feed
        if path == '/api/threat-intelligence':
            self.send_json({
                "total_records": 12,
                "environment": "Simulated Enterprise SOC Feed",
                "disclaimer": "Simulated Threat Intelligence for Cybersecurity Demonstration and Research",
                "indicators": [
                    {
                        "indicator": "secure-globex-approval.com",
                        "type": "Domain",
                        "threat_category": "Phishing / BEC Lookalike",
                        "severity": "Critical",
                        "source": "SOC Honeypot Telemetry",
                        "first_seen": "2026-09-28T14:22:00Z",
                        "last_seen": "2026-10-01T08:15:00Z",
                        "confidence": 98
                    },
                    {
                        "indicator": "185.220.101.45",
                        "type": "IPv4",
                        "threat_category": "Bulletproof SMTP Relay",
                        "severity": "High",
                        "source": "AbuseIPDB Feed",
                        "first_seen": "2026-09-15T03:10:00Z",
                        "last_seen": "2026-10-01T11:40:00Z",
                        "confidence": 94
                    },
                    {
                        "indicator": "http://194.26.29.112/wire-docs/summary.pdf",
                        "type": "URL",
                        "threat_category": "Direct-IP Malware Delivery",
                        "severity": "Critical",
                        "source": "URLhaus Tracker",
                        "first_seen": "2026-09-30T22:11:00Z",
                        "last_seen": "2026-10-01T14:02:00Z",
                        "confidence": 99
                    },
                    {
                        "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "type": "File Hash (SHA-256)",
                        "threat_category": "AgentTesla ISO Dropper",
                        "severity": "Critical",
                        "source": "MalwareBazaar",
                        "first_seen": "2026-09-29T18:05:00Z",
                        "last_seen": "2026-10-01T09:30:00Z",
                        "confidence": 96
                    },
                    {
                        "indicator": "paypal-security-alert-center.info",
                        "type": "Domain",
                        "threat_category": "Credential Harvesting",
                        "severity": "High",
                        "source": "OpenPhish Live Feed",
                        "first_seen": "2026-09-25T07:14:00Z",
                        "last_seen": "2026-09-30T19:50:00Z",
                        "confidence": 92
                    },
                    {
                        "indicator": "transfer-clearance@stealth-wire-service.net",
                        "type": "Email Address",
                        "threat_category": "Impersonation / BEC Collector",
                        "severity": "Critical",
                        "source": "Internal SOC Incident",
                        "first_seen": "2026-09-27T11:00:00Z",
                        "last_seen": "2026-10-01T08:30:00Z",
                        "confidence": 95
                    }
                ]
            })
            return

        # Geolocation query
        if path.startswith('/api/geolocation/'):
            ip = path.replace('/api/geolocation/', '').strip()
            data = mock_ip_lookup(ip)
            self.send_json(data)
            return

        self.send_json({"error": "Endpoint not recognized"}, 404)

    def handle_api_post(self):
        path = self.path.split('?')[0]
        content_length = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_length).decode('utf-8', errors='ignore')

        if path == '/api/analyze-email':
            try:
                # Parse JSON or raw EML
                eml_content = post_body
                if post_body.strip().startswith('{'):
                    parsed_json = json.loads(post_body)
                    eml_content = parsed_json.get('eml_raw', '') or parsed_json.get('headers', '')
                
                # Use python's email parser
                msg = email.message_from_string(eml_content, policy=policy.default)
                
                subject = str(msg.get('Subject', 'No Subject Specified'))
                sender = str(msg.get('From', 'Unknown Sender'))
                recipient = str(msg.get('To', 'Unknown Recipient'))
                reply_to = str(msg.get('Reply-To', ''))
                return_path = str(msg.get('Return-Path', ''))
                date_str = str(msg.get('Date', datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")))
                message_id = str(msg.get('Message-ID', f"<{calculate_sha256(sender + subject)[:16]}@cyber-telemetry>"))
                
                # Check for Received headers
                received_headers = msg.get_all('Received', [])
                
                # Simple extraction of IPs and URLs
                all_text = eml_content
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                url_pattern = r'https?://[^\s<>"\']+'
                
                found_ips = list(set(re.findall(ip_pattern, all_text)))
                # Filter internal non-routable IPs like 127.0.0.1 if others exist
                public_ips = [ip for ip in found_ips if not ip.startswith(('127.', '10.', '192.168.', '0.'))]
                if not public_ips:
                    public_ips = found_ips or ["185.220.101.45"]
                
                found_urls = list(set(re.findall(url_pattern, all_text)))
                
                # Compute Threat Score based on heuristics
                risk_score = 15
                threat_reasons = []
                detected_threats = []
                
                # Heuristic 1: Reply-To mismatch
                if reply_to and sender:
                    sender_domain = sender.split('@')[-1].replace('>', '').strip().lower()
                    reply_domain = reply_to.split('@')[-1].replace('>', '').strip().lower()
                    if sender_domain and reply_domain and sender_domain != reply_domain:
                        risk_score += 28
                        threat_reasons.append(f"Mismatched Reply-To address detected ({reply_domain} vs {sender_domain})")
                        detected_threats.append({
                            "name": "Spoofing / Impersonation",
                            "severity": "High",
                            "confidence": 94,
                            "explanation": "Return path/reply recipient differs from the apparent sender identity.",
                            "evidence": [f"From domain: {sender_domain}", f"Reply-To domain: {reply_domain}"]
                        })
                
                # Heuristic 2: Suspicious & urgent keywords
                urgent_keywords = ['urgent', 'wire transfer', 'suspended', 'verify account', 'unauthorized', 'immediate action', 'invoice', 'password', 'banking', 'routing instructions', 'authenticator', 'action required', 'restore access']
                matched_keywords = [kw for kw in urgent_keywords if kw in (subject + " " + all_text).lower()]
                if matched_keywords:
                    risk_score += min(len(matched_keywords) * 12, 36)
                    threat_reasons.append(f"Urgent coercive language identified: {', '.join(matched_keywords)}")
                    detected_threats.append({
                        "name": "Phishing / Social Engineering",
                        "severity": "High",
                        "confidence": 92,
                        "explanation": "High-urgency psychological triggers designed to bypass security checks.",
                        "evidence": [f"Keywords detected: {', '.join(matched_keywords)}"]
                    })
                
                # Heuristic 3: Brand lookalike / Credential Harvesting
                brand_keywords = ['paypal', 'microsoft', 'apple', 'google', 'chase', 'bank']
                sender_lower = sender.lower()
                matched_brands = [b for b in brand_keywords if b in sender_lower or b in subject.lower()]
                if matched_brands:
                    # Check if domain is legitimate or third-party lookalike
                    sender_domain = sender.split('@')[-1].replace('>', '').strip().lower() if '@' in sender else ""
                    legit_domains = ['paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'chase.com']
                    if sender_domain and not any(sender_domain.endswith(ld) for ld in legit_domains):
                        risk_score += 26
                        threat_reasons.append(f"Suspected brand impersonation: '{matched_brands[0]}' in unauthorized domain '{sender_domain}'")
                        detected_threats.append({
                            "name": "Credential Theft / Brand Impersonation",
                            "severity": "Critical",
                            "confidence": 95,
                            "explanation": f"Unauthorized domain masquerading as trusted brand {matched_brands[0]}.",
                            "evidence": [f"Sender claims brand identity '{matched_brands[0]}'", f"Domain '{sender_domain}' is not official infrastructure"]
                        })

                # Heuristic 4: Financial diversion & wire instructions
                fin_keywords = ['routing number', 'swift code', 'beneficiary bank', 'new clearing facility', 'disbursements']
                if any(fk in all_text.lower() for fk in fin_keywords):
                    risk_score += 24
                    threat_reasons.append("Unauthorized banking/routing redirection detected.")
                    detected_threats.append({
                        "name": "Business Email Compromise (BEC)",
                        "severity": "Critical",
                        "confidence": 96,
                        "explanation": "Fraudulent payment diversion instructions targeting financial operations.",
                        "evidence": ["Altered routing/clearing instructions detected in email body"]
                    })

                # Heuristic 5: Suspicious attachments or ISO/EXE
                if any(ext in all_text.lower() for ext in ['.iso', '.exe', '.scr', '.vbs', '.bat', '.xlsm']):
                    risk_score += 30
                    threat_reasons.append("High-risk attachment container (.iso / .exe / .xlsm / script) detected in MIME payload.")
                    detected_threats.append({
                        "name": "Malware Delivery",
                        "severity": "Critical",
                        "confidence": 96,
                        "explanation": "Executable archive or macro script designed to bypass standard mail filtering engines.",
                        "evidence": ["High-risk extension detected in MIME headers"]
                    })

                # Cap score
                risk_score = min(max(risk_score, 12), 97)
                
                # Determine state
                if risk_score < 20:
                    state = "SAFE"
                elif risk_score < 40:
                    state = "LOW RISK"
                elif risk_score < 60:
                    state = "SUSPICIOUS"
                elif risk_score < 80:
                    state = "HIGH RISK"
                else:
                    state = "CRITICAL"
                
                report = {
                    "case_id": f"IG-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{calculate_sha256(subject)[:6].upper()}",
                    "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
                    "email_metadata": {
                        "subject": subject,
                        "from": sender,
                        "to": recipient,
                        "reply_to": reply_to or "None specified",
                        "return_path": return_path or "None specified",
                        "date": date_str,
                        "message_id": message_id,
                        "received_count": len(received_headers),
                        "url_count": len(found_urls),
                        "ip_count": len(public_ips)
                    },
                    "risk_evaluation": {
                        "score": risk_score,
                        "state": state,
                        "threat_count": len(detected_threats),
                        "explanation": "; ".join(threat_reasons) if threat_reasons else "Standard compliance checks passed with no significant anomalies detected."
                    },
                    "detected_threats": detected_threats,
                    "authentication": {
                        "spf": {"status": "FAIL" if risk_score > 50 else "PASS", "domain": sender.split('@')[-1].replace('>', '') if '@' in sender else "domain.com", "alignment": "Unaligned" if risk_score > 50 else "Aligned"},
                        "dkim": {"status": "FAIL" if risk_score > 50 else "PASS", "selector": "s2024", "valid": risk_score <= 50},
                        "dmarc": {"status": "FAIL" if risk_score > 50 else "PASS", "policy": "reject", "disposition": "Quarantined" if risk_score > 50 else "Delivered"}
                    },
                    "geolocations": [mock_ip_lookup(ip) for ip in public_ips[:4]],
                    "urls": found_urls,
                    "disclaimer": "Simulated Forensic Intelligence for Cybersecurity Research & Demonstration"
                }

                self.send_json(report)
            except Exception as e:
                self.send_json({"error": f"Failed to parse email: {str(e)}"}, 400)
            return

        self.send_json({"error": "Endpoint not recognized"}, 404)

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), InboxGuardianHandler) as httpd:
        print(f"[+] Inbox Guardian Cybersecurity Server running at http://127.0.0.1:{PORT}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[-] Server shutting down gracefully.")
