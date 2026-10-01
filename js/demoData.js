/**
 * Inbox Guardian - Forensic Demo Intelligence Datasets
 * Highly realistic simulated enterprise email threat cases, geolocations, and IOCs.
 * All domains, IPs, and identities are fictional and clearly marked for demonstration.
 */

const DEMO_CRITICAL_PHISH = {
  case_id: "IG-20261001-CRIT-94F",
  investigator: "Analyst Tier-3 / SOC Ops (Simulation)",
  analysis_timestamp: "2026-10-01T09:18:44Z",
  eml_filename: "urgent_wire_transfer_bec.eml",
  email_metadata: {
    subject: "URGENT: Executive Wire Transfer Authorization Required - Ref #INV-88392",
    from: "Johnathan Davis <ceo@globex-corp-finance.co>",
    to: "Emily Watson <emily.watson@globex-corp.com>",
    cc: "None",
    reply_to: "transfer-clearance@stealth-wire-service.net",
    return_path: "bounce-agent@bulletproof-relay.ru",
    date: "Thu, 01 Oct 2026 09:14:22 -0400",
    message_id: "<20261001091422.9F82A1@globex-corp-finance.co>",
    mailer: "Thunderbird 115.3.1 (Spoofed Header)",
    hop_count: 3,
    url_count: 3,
    attachment_count: 1,
    ip_count: 3
  },
  risk_evaluation: {
    score: 87,
    state: "CRITICAL",
    confidence: 94,
    threat_icon: "shield-alert",
    explanation: "Multiple critical threat vectors detected: high-profile executive impersonation (CEO fraud / BEC), domain typosquatting, deceptive Reply-To rerouting, and a weaponized ISO disc image attachment disguised as a PDF invoice.",
    detected_evidence_count: 8,
    breakdown: {
      domain_reputation: 92,
      authentication_failure: 95,
      content_urgency: 88,
      attachment_risk: 98,
      link_suspicion: 86
    }
  },
  detected_threats: [
    {
      name: "Business Email Compromise (BEC)",
      severity: "Critical",
      confidence: 96,
      icon: "user-x",
      explanation: "Direct executive impersonation targeting the finance department for unauthorized capital disbursement.",
      evidence: [
        "Sender displays CEO identity: 'Johnathan Davis'",
        "Demands immediate wire transfer of $148,500 USD before banking close",
        "Instructs recipient to bypass standard dual-authorization protocols due to confidential acquisition"
      ]
    },
    {
      name: "Phishing / Social Engineering",
      severity: "Critical",
      confidence: 94,
      icon: "hook",
      explanation: "Coercive psychological manipulation combined with credential-harvesting authorization portal.",
      evidence: [
        "Urgent timeline pressure: 'Execute within 45 minutes'",
        "Lookalike domain registered only 4 days ago ('globex-corp-finance.co' vs legitimate 'globex-corp.com')",
        "Fake corporate authorization portal hosted on untrusted infrastructure"
      ]
    },
    {
      name: "Spoofing & Return-Path Anomaly",
      severity: "High",
      confidence: 92,
      icon: "repeat",
      explanation: "Header From domain differs completely from Reply-To and Return-Path destinations.",
      evidence: [
        "From domain: globex-corp-finance.co",
        "Reply-To: transfer-clearance@stealth-wire-service.net (External stealth recipient)",
        "Return-Path: bounce-agent@bulletproof-relay.ru (Known Russian bulletproof provider)"
      ]
    },
    {
      name: "Malware Delivery via Container",
      severity: "Critical",
      confidence: 98,
      icon: "bug",
      explanation: "High-risk disc image attachment containing an executable payload designed to bypass email perimeter filters.",
      evidence: [
        "Attachment name: Wire_Payment_Order_INV88392.pdf.iso",
        "Double extension trick: .pdf.iso",
        "Contains payload matching AgentTesla / Formbook infostealer signatures"
      ]
    },
    {
      name: "Deceptive Malicious Links",
      severity: "High",
      confidence: 89,
      icon: "link-2",
      explanation: "Email body contains obfuscated URL shortener redirecting to an unauthorized external IP server.",
      evidence: [
        "Shortened URL: https://bit.ly/3xGlobexTransfer",
        "Target endpoint: http://194.26.29.112/wire-docs/summary.pdf",
        "Direct-to-IP URL format violates enterprise browsing policy"
      ]
    }
  ],
  authentication: {
    spf: {
      status: "FAIL",
      domain: "globex-corp-finance.co",
      client_ip: "185.220.101.45",
      mechanism: "-all",
      explanation: "Sender IP 185.220.101.45 is not authorized by the designated domain's SPF record.",
      alignment: "FAIL (Unaligned with RFC5322 From)"
    },
    dkim: {
      status: "FAIL",
      selector: "s2024",
      domain: "globex-corp-finance.co",
      signature_valid: false,
      algorithm: "rsa-sha256",
      explanation: "DKIM signature failed cryptographic hash verification. Message body or headers were modified in transit.",
      alignment: "FAIL"
    },
    dmarc: {
      status: "FAIL",
      policy: "reject",
      disposition: "QUARANTINE_RECOMMENDED",
      spf_align: "fail",
      dkim_align: "fail",
      explanation: "Both SPF and DKIM fail domain alignment with From header. Domain policy dictates rejection.",
      alignment: "FAIL"
    }
  },
  header_forensics: {
    originating_ip: "185.220.101.45",
    sending_server: "mail-relay4.bulletproof-m247.net",
    relay_path: [
      {
        hop: 1,
        server: "smtp.m247-transit.ro (185.220.101.45)",
        by: "relay-de.core-cluster.net",
        timestamp: "01 Oct 2026 09:14:24 -0400",
        delay_ms: 120,
        tls: "TLSv1.2 (ECDHE-RSA-AES256-GCM-SHA384)",
        role: "Email Origin (Adversary Relay)"
      },
      {
        hop: 2,
        server: "relay-de.core-cluster.net (198.51.100.24)",
        by: "mx-edge-va.cloudflare-defense.net",
        timestamp: "01 Oct 2026 09:14:26 -0400",
        delay_ms: 480,
        tls: "TLSv1.3 (TLS_AES_256_GCM_SHA384)",
        role: "Intermediate Gateway Relay"
      },
      {
        hop: 3,
        server: "mx-edge-va.cloudflare-defense.net (104.244.42.1)",
        by: "mail.globex-corp.com",
        timestamp: "01 Oct 2026 09:14:27 -0400",
        delay_ms: 210,
        tls: "TLSv1.3 (TLS_AES_256_GCM_SHA384)",
        role: "Enterprise Ingress MX"
      }
    ]
  },
  urls: [
    {
      url: "https://secure-globex-approval.com/authorize?token=9f82d1",
      domain: "secure-globex-approval.com",
      protocol: "HTTPS",
      reputation: "Malicious (Brand Impersonation)",
      suspicion_score: 95,
      redirects: 0,
      status: "Active Phishing Host",
      indicators: ["Newly Registered (<4 days)", "Typo/Brand Impersonation", "SSL Issuer: Let's Encrypt (Free)", "Direct credential POST handler"]
    },
    {
      url: "http://194.26.29.112/wire-docs/summary.pdf",
      domain: "194.26.29.112 (Direct IP)",
      protocol: "HTTP (Insecure)",
      reputation: "Critical Threat",
      suspicion_score: 98,
      redirects: 1,
      status: "Malware Host",
      indicators: ["Raw IPv4 Host", "Non-HTTPS Protocol", "Known C2 Distribution Node", "Port 80 Insecure Download"]
    },
    {
      url: "https://bit.ly/3xGlobexTransfer",
      domain: "bit.ly",
      protocol: "HTTPS",
      reputation: "High Suspicion (Obfuscated)",
      suspicion_score: 82,
      redirects: 2,
      status: "Redirect Chain",
      indicators: ["Shortened URL", "Conceals Dest IP 194.26.29.112", "Evasion of URL Perimeter Filters"]
    }
  ],
  geolocations: [
    {
      ip: "185.220.101.45",
      type: "Origin IP",
      country: "Romania",
      country_code: "RO",
      city: "Bucharest",
      region: "Ilfov County",
      latitude: 44.4268,
      longitude: 26.1025,
      isp: "M247 Europe Ltd",
      asn: "AS200052",
      organization: "Known Tor Exit & Adversary SMTP Infrastructure",
      risk_score: 89,
      reputation: "Malicious / Bulletproof Host",
      abuse_score: 89,
      disclaimer: "Approximate BGP routing location; not a physical GPS coordinate."
    },
    {
      ip: "198.51.100.24",
      type: "Intermediate Relay",
      country: "Germany",
      country_code: "DE",
      city: "Frankfurt am Main",
      region: "Hesse",
      latitude: 50.1109,
      longitude: 8.6821,
      isp: "Equinix Frankfurt Gateway",
      asn: "AS8075",
      organization: "Intermediate SMTP Transit Backbone",
      risk_score: 45,
      reputation: "Suspicious Transit",
      abuse_score: 18,
      disclaimer: "Approximate BGP routing location."
    },
    {
      ip: "104.244.42.1",
      type: "Ingress Destination",
      country: "United States",
      country_code: "US",
      city: "Ashburn",
      region: "Virginia",
      latitude: 39.0438,
      longitude: -77.4874,
      isp: "Cloudflare Ingress Protection",
      asn: "AS13335",
      organization: "Enterprise Edge Mail Filter",
      risk_score: 8,
      reputation: "Clean / Enterprise Gateway",
      abuse_score: 0,
      disclaimer: "Approximate BGP routing location."
    }
  ],
  attachments: [
    {
      filename: "Wire_Payment_Order_INV88392.pdf.iso",
      type: "Disc Image (ISO)",
      size: "4.2 MB",
      mime: "application/x-iso9660-image",
      hash_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      hash_md5: "d41d8cd98f00b204e9800998ecf8427e",
      risk_state: "MALICIOUS",
      status_badge: "High Risk File Extension",
      indicators: [
        "Dangerous double extension (.pdf.iso)",
        "Mountable ISO container bypasses email sandbox static scanners",
        "Internal payload contains embedded payload: Payment_Process.exe",
        "Static signature matches AgentTesla Infostealer variant"
      ]
    }
  ],
  iocs: [
    { type: "IP", value: "185.220.101.45", category: "Adversary Origin Relay", threat: "Critical" },
    { type: "IP", value: "194.26.29.112", category: "Malware C2 Host", threat: "Critical" },
    { type: "Domain", value: "globex-corp-finance.co", category: "Typo/Lookalike Domain", threat: "High" },
    { type: "Domain", value: "secure-globex-approval.com", category: "Phishing Portal", threat: "Critical" },
    { type: "Domain", value: "stealth-wire-service.net", category: "Deceptive Reply-To", threat: "Critical" },
    { type: "URL", value: "https://secure-globex-approval.com/authorize?token=9f82d1", category: "Credential Harvester", threat: "Critical" },
    { type: "URL", value: "http://194.26.29.112/wire-docs/summary.pdf", category: "Direct-IP Malware URL", threat: "Critical" },
    { type: "URL", value: "https://bit.ly/3xGlobexTransfer", category: "Obfuscated Shortener", threat: "High" },
    { type: "Email", value: "ceo@globex-corp-finance.co", category: "Spoofed Sender", threat: "High" },
    { type: "Email", value: "transfer-clearance@stealth-wire-service.net", category: "Collector Inbox", threat: "Critical" },
    { type: "Hash", value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", category: "SHA-256 (AgentTesla ISO)", threat: "Critical" }
  ],
  forensic_timeline: [
    { step: 1, title: "Email Dispatched from Origin", time: "09:14:22 UTC", desc: "Adversary SMTP server 185.220.101.45 in Bucharest, Romania injects forged message into transit." },
    { step: 2, title: "Header Ingestion & Relay", time: "09:14:24 UTC", desc: "Equinix Frankfurt node receives envelope; modifies Received header chain." },
    { step: 3, title: "Authentication Check Triggered", time: "09:14:26 UTC", desc: "Inbound SPF evaluation checks 185.220.101.45 against domain globex-corp-finance.co. Result: FAIL." },
    { step: 4, title: "DKIM Signature Verification", time: "09:14:26 UTC", desc: "Public key selector s2024 fails body hash comparison. Result: INVALID." },
    { step: 5, title: "Domain Intelligence Correlation", time: "09:14:27 UTC", desc: "Sender domain 'globex-corp-finance.co' flagged as lookalike typo of legitimate organization domain." },
    { step: 6, title: "URL Deep Scan & Expansion", time: "09:14:27 UTC", desc: "Bitly shortener resolved to direct HTTP IPv4 address 194.26.29.112 hosting executable file." },
    { step: 7, title: "Attachment Static Analysis", time: "09:14:28 UTC", desc: "Discovered mountable .ISO container file. Static hashing matches known infostealer family." },
    { step: 8, title: "Threat Classification & Forensic Report", time: "09:14:28 UTC", desc: "Overall Risk Score evaluated at 87 (CRITICAL). Incident containment playbook initiated." }
  ],
  recommendations: [
    { title: "Immediate Mailbox Purge", desc: "Execute global Exchange/Google Workspace tenant search-and-purge for Message-ID <20261001091422.9F82A1@globex-corp-finance.co>." },
    { title: "Firewall & Egress Block", desc: "Add IPs 185.220.101.45 and 194.26.29.112 to perimeter firewall dropping table across all corporate networks." },
    { title: "DNS Sinkhole", desc: "Sinkhole domains secure-globex-approval.com and globex-corp-finance.co at internal recursive resolvers." },
    { title: "Finance Staff Alert", desc: "Notify recipient Emily Watson and finance personnel regarding active CEO impersonation and wire transfer fraud attempt." },
    { title: "Endpoint Threat Hunt", desc: "Scan all endpoints for execution traces of SHA-256 hash e3b0c442... and ISO mounting events in Windows Event Viewer (Event ID 12)." }
  ]
};

const DEMO_SAFE_CORPORATE = {
  case_id: "IG-20261001-SAFE-12C",
  investigator: "Analyst Tier-3 / SOC Ops (Simulation)",
  analysis_timestamp: "2026-10-01T10:04:12Z",
  eml_filename: "quarterly_compliance_update.eml",
  email_metadata: {
    subject: "Quarterly Security Compliance Review - Q3 Results & Action Plan",
    from: "Marcus Vance <ciso@cyber-defense.org>",
    to: "Security Steering Committee <steering@cyber-defense.org>",
    cc: "None",
    reply_to: "ciso@cyber-defense.org",
    return_path: "ciso@cyber-defense.org",
    date: "Thu, 01 Oct 2026 10:01:00 -0400",
    message_id: "<corp.20261001.100100@cyber-defense.org>",
    mailer: "Microsoft Outlook 16.0",
    hop_count: 2,
    url_count: 1,
    attachment_count: 1,
    ip_count: 2
  },
  risk_evaluation: {
    score: 12,
    state: "SAFE",
    confidence: 98,
    threat_icon: "shield-check",
    explanation: "Email passed all enterprise authentication checks (SPF, DKIM, DMARC passing with strict alignment). Originating IP is verified legitimate corporate infrastructure with zero abuse history.",
    detected_evidence_count: 0,
    breakdown: {
      domain_reputation: 6,
      authentication_failure: 0,
      content_urgency: 4,
      attachment_risk: 8,
      link_suspicion: 2
    }
  },
  detected_threats: [],
  authentication: {
    spf: {
      status: "PASS",
      domain: "cyber-defense.org",
      client_ip: "40.92.18.52",
      mechanism: "include:spf.protection.outlook.com",
      explanation: "Sender IP is authorized by the designated SPF record.",
      alignment: "PASS (Strict alignment)"
    },
    dkim: {
      status: "PASS",
      selector: "selector1-cyberdefense",
      domain: "cyber-defense.org",
      signature_valid: true,
      algorithm: "rsa-sha256",
      explanation: "Cryptographic signature validated successfully against public key.",
      alignment: "PASS"
    },
    dmarc: {
      status: "PASS",
      policy: "reject",
      disposition: "NONE (Delivered)",
      spf_align: "pass",
      dkim_align: "pass",
      explanation: "Both SPF and DKIM pass with full domain alignment.",
      alignment: "PASS"
    }
  },
  header_forensics: {
    originating_ip: "40.92.18.52",
    sending_server: "mail-eop.protection.outlook.com",
    relay_path: [
      {
        hop: 1,
        server: "outlook-client.corp.internal (40.92.18.52)",
        by: "eop-nam04.protection.outlook.com",
        timestamp: "01 Oct 2026 10:01:02 -0400",
        delay_ms: 95,
        tls: "TLSv1.3",
        role: "Corporate O365 Tenant"
      },
      {
        hop: 2,
        server: "eop-nam04.protection.outlook.com (104.244.42.1)",
        by: "mail.cyber-defense.org",
        timestamp: "01 Oct 2026 10:01:04 -0400",
        delay_ms: 110,
        tls: "TLSv1.3",
        role: "Destination Inbound Gateway"
      }
    ]
  },
  urls: [
    {
      url: "https://portal.cyber-defense.org/compliance/q3-summary",
      domain: "portal.cyber-defense.org",
      protocol: "HTTPS",
      reputation: "Clean Corporate Asset",
      suspicion_score: 5,
      redirects: 0,
      status: "Verified Internal Host",
      indicators: ["Enterprise Subdomain", "Valid EV SSL Certificate", "Internal SSO Protected"]
    }
  ],
  geolocations: [
    {
      ip: "40.92.18.52",
      type: "Originating Server",
      country: "United States",
      country_code: "US",
      city: "Redmond",
      region: "Washington",
      latitude: 47.6740,
      longitude: -122.1215,
      isp: "Microsoft Corporation",
      asn: "AS8075",
      organization: "Microsoft 365 Exchange Online",
      risk_score: 2,
      reputation: "Verified Clean",
      abuse_score: 0,
      disclaimer: "Approximate BGP routing location."
    }
  ],
  attachments: [
    {
      filename: "Q3_Compliance_Audit_Matrix.pdf",
      type: "Adobe Acrobat PDF Document",
      size: "842 KB",
      mime: "application/pdf",
      hash_sha256: "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
      hash_md5: "b10a8db164e0754105b7a99be72e3fe5",
      risk_state: "SAFE",
      status_badge: "Clean Document",
      indicators: ["Zero embedded JavaScript", "No launch actions or macro containers", "Standard PDF 1.7 structure"]
    }
  ],
  iocs: [],
  forensic_timeline: [
    { step: 1, title: "Message Ingestion", time: "10:01:00 UTC", desc: "Corporate Exchange Online tenant receives outbound draft." },
    { step: 2, title: "DKIM Signature Applied", time: "10:01:01 UTC", desc: "Selector selector1-cyberdefense signs message headers with 2048-bit RSA." },
    { step: 3, title: "Perimeter Delivery", time: "10:01:04 UTC", desc: "SPF and DMARC verified clean. Dispatched to committee recipient list." }
  ],
  recommendations: [
    { title: "Standard Processing", desc: "No defensive containment or firewall blocking necessary. Message verified legitimate." }
  ]
};

const DEMO_MALWARE_INVOICE = {
  case_id: "IG-20261001-MALW-92E",
  investigator: "Analyst Tier-3 / SOC Ops (Simulation)",
  analysis_timestamp: "2026-10-01T11:22:15Z",
  eml_filename: "overdue_invoice_remittance.eml",
  email_metadata: {
    subject: "Overdue Remittance Notice: Invoice #INV-2026-0921 Past Due",
    from: "Accounts Receivable <billing@supplier-cloud-portal.xyz>",
    to: "accounting@enterprise-corp.com",
    cc: "None",
    reply_to: "recovery@offshore-accounting-dept.cc",
    return_path: "bounce@host-cluster-98.ru",
    date: "Thu, 01 Oct 2026 11:15:30 -0400",
    message_id: "<20261001111530.44910@supplier-cloud-portal.xyz>",
    mailer: "PHPMailer 6.5.0",
    hop_count: 3,
    url_count: 2,
    attachment_count: 1,
    ip_count: 3
  },
  risk_evaluation: {
    score: 92,
    state: "CRITICAL",
    confidence: 97,
    threat_icon: "bug",
    explanation: "Critical weaponized malware delivery campaign. Email contains an encrypted ZIP archive containing a VBScript/PowerShell multi-stage dropper contacting an offshore command-and-control server.",
    detected_evidence_count: 9,
    breakdown: {
      domain_reputation: 96,
      authentication_failure: 98,
      content_urgency: 90,
      attachment_risk: 99,
      link_suspicion: 91
    }
  },
  detected_threats: [
    {
      name: "Malware Delivery (Infostealer / Loader)",
      severity: "Critical",
      confidence: 98,
      icon: "bug",
      explanation: "Encrypted attachment contains a weaponized script dropper disguised as an overdue invoice.",
      evidence: [
        "Attachment name: Remittance_Invoice_Overdue.zip",
        "Archive payload: Invoice_Details.vbs (Visual Basic script)",
        "Script issues obfuscated PowerShell download cradle targeting 194.26.29.112"
      ]
    },
    {
      name: "Suspicious Top-Level Domain (TLD)",
      severity: "High",
      confidence: 91,
      icon: "alert-triangle",
      explanation: "Sender and Reply-To use low-reputation disposable TLDs (.xyz and .cc).",
      evidence: [
        "Sender: supplier-cloud-portal.xyz",
        "Reply-To: offshore-accounting-dept.cc",
        "Both domains registered within the last 72 hours"
      ]
    }
  ],
  authentication: {
    spf: { status: "FAIL", domain: "supplier-cloud-portal.xyz", client_ip: "91.240.118.82", mechanism: "-all", explanation: "SPF check failed. IP not authorized.", alignment: "FAIL" },
    dkim: { status: "FAIL", selector: "default", domain: "supplier-cloud-portal.xyz", signature_valid: false, explanation: "No valid DKIM signature found.", alignment: "FAIL" },
    dmarc: { status: "FAIL", policy: "none", disposition: "MONITOR", explanation: "DMARC policy absent or failing alignment.", alignment: "FAIL" }
  },
  header_forensics: {
    originating_ip: "91.240.118.82",
    sending_server: "vps91.bulletproof-host.ru",
    relay_path: [
      { hop: 1, server: "vps91.bulletproof-host.ru (91.240.118.82)", by: "mx.transit-node.nl", timestamp: "01 Oct 2026 11:15:32 -0400", delay_ms: 180, tls: "TLSv1.2", role: "Origin Adversary VPS" },
      { hop: 2, server: "mx.transit-node.nl (45.133.1.9)", by: "gateway.enterprise-corp.com", timestamp: "01 Oct 2026 11:15:34 -0400", delay_ms: 220, tls: "TLSv1.3", role: "Intermediate Relay" }
    ]
  },
  urls: [
    {
      url: "http://194.26.29.112/payload/invoice.exe",
      domain: "194.26.29.112",
      protocol: "HTTP",
      reputation: "Critical Threat (Malware C2)",
      suspicion_score: 99,
      redirects: 0,
      status: "Active Dropper C2",
      indicators: ["Direct IPv4", "Unencrypted Binary Download", "Blacklisted by CERT-CC"]
    }
  ],
  geolocations: [
    {
      ip: "91.240.118.82",
      type: "Origin IP",
      country: "Russia",
      country_code: "RU",
      city: "Moscow",
      region: "Moscow City",
      latitude: 55.7558,
      longitude: 37.6173,
      isp: "Selectel Infrastructure",
      asn: "AS49505",
      organization: "Adversary Bulletproof VPS Node",
      risk_score: 94,
      reputation: "Known Threat Actor Host",
      abuse_score: 95,
      disclaimer: "Approximate BGP routing location."
    }
  ],
  attachments: [
    {
      filename: "Remittance_Invoice_Overdue.zip",
      type: "ZIP Compressed Archive",
      size: "1.8 MB",
      mime: "application/zip",
      hash_sha256: "b45c389f41d9e2b109341ef94821a049102c89fae12089b3842109e90145cbe2",
      hash_md5: "c0182498102481024981024981024981",
      risk_state: "MALICIOUS",
      status_badge: "Executable Script Container",
      indicators: ["Contains Invoice_Details.vbs", "Script initiates web client download cradle", "High entropy in binary payload"]
    }
  ],
  iocs: [
    { type: "IP", value: "91.240.118.82", category: "Adversary Origin VPS", threat: "Critical" },
    { type: "IP", value: "194.26.29.112", category: "Malware Download C2", threat: "Critical" },
    { type: "Domain", value: "supplier-cloud-portal.xyz", category: "Phishing Domain", threat: "High" },
    { type: "Domain", value: "offshore-accounting-dept.cc", category: "Harvesting Inbox", threat: "Critical" },
    { type: "Hash", value: "b45c389f41d9e2b109341ef94821a049102c89fae12089b3842109e90145cbe2", category: "SHA-256 (Malware ZIP)", threat: "Critical" }
  ],
  forensic_timeline: [
    { step: 1, title: "Adversary Ingestion", time: "11:15:30 UTC", desc: "Selectel VPS node dispatches mass invoice spoofing run." },
    { step: 2, title: "Static Filter Analysis", time: "11:15:33 UTC", desc: "Archive inspected. Uncompressed VBS script contains malicious PowerShell cradle." },
    { step: 3, title: "C2 Correlation", time: "11:15:34 UTC", desc: "Download endpoint 194.26.29.112 matches known RedLine Stealer distributor." }
  ],
  recommendations: [
    { title: "Block Disposable TLDs", desc: "Enforce policy rule dropping incoming external mail originating from .xyz, .cc, and .top TLDs without prior vendor whitelist." },
    { title: "Quarantine Archive Executables", desc: "Enforce gateway rule disallowing incoming ZIP files containing .vbs, .bat, or .js files." }
  ]
};

// Global Threat Intelligence Feed for the Threat Intel Page
const GLOBAL_THREAT_FEEDS = [
  {
    indicator: "secure-globex-approval.com",
    type: "Domain",
    category: "Phishing / BEC Lookalike",
    severity: "Critical",
    source: "SOC Honeypot Telemetry",
    first_seen: "2026-09-28 14:22:00",
    last_seen: "2026-10-01 08:15:00",
    confidence: 98
  },
  {
    indicator: "185.220.101.45",
    type: "IPv4 Address",
    category: "Bulletproof SMTP Relay",
    severity: "High",
    source: "AbuseIPDB Global",
    first_seen: "2026-09-15 03:10:00",
    last_seen: "2026-10-01 11:40:00",
    confidence: 94
  },
  {
    indicator: "http://194.26.29.112/wire-docs/summary.pdf",
    type: "URL",
    category: "Direct-IP Malware Delivery",
    severity: "Critical",
    source: "URLhaus Feed",
    first_seen: "2026-09-30 22:11:00",
    last_seen: "2026-10-01 14:02:00",
    confidence: 99
  },
  {
    indicator: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    type: "File Hash (SHA-256)",
    category: "AgentTesla ISO Dropper",
    severity: "Critical",
    source: "MalwareBazaar",
    first_seen: "2026-09-29 18:05:00",
    last_seen: "2026-10-01 09:30:00",
    confidence: 96
  },
  {
    indicator: "paypal-security-alert-center.info",
    type: "Domain",
    category: "Credential Harvesting",
    severity: "High",
    source: "OpenPhish Telemetry",
    first_seen: "2026-09-25 07:14:00",
    last_seen: "2026-09-30 19:50:00",
    confidence: 92
  },
  {
    indicator: "transfer-clearance@stealth-wire-service.net",
    type: "Email Address",
    category: "Impersonation / BEC Collector",
    severity: "Critical",
    source: "SOC Internal Incident",
    first_seen: "2026-09-27 11:00:00",
    last_seen: "2026-10-01 08:30:00",
    confidence: 95
  },
  {
    indicator: "91.240.118.82",
    type: "IPv4 Address",
    category: "Ransomware Distribution Node",
    severity: "Critical",
    source: "ThreatFox Abuse Feed",
    first_seen: "2026-09-20 01:45:00",
    last_seen: "2026-10-01 12:10:00",
    confidence: 97
  },
  {
    indicator: "account-verify-microsoft365.online",
    type: "Domain",
    category: "M365 OAuth Token Phish",
    severity: "High",
    source: "Microsoft Defender Intel",
    first_seen: "2026-09-29 16:30:00",
    last_seen: "2026-10-01 13:00:00",
    confidence: 93
  }
];
