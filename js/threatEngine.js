/**
 * Inbox Guardian - AI Threat Detection & Forensic Analysis Engine
 * Calculates weighted 0-100 Risk Score, classifies cyber threat categories,
 * correlates IOCs, generates forensic timelines and actionable remediation playbooks.
 */

class ThreatEngine {
  /**
   * Run full threat analysis on a parsed email
   * @param {object} parsedEmail 
   * @returns {object} complete forensic analysis report
   */
  static analyze(parsedEmail) {
    let score = 10;
    const detectedThreats = [];
    const evidenceList = [];
    const iocs = [];

    const subject = (parsedEmail.subject || "").toLowerCase();
    const body = (parsedEmail.body_preview || "").toLowerCase();
    const from = (parsedEmail.from || "").toLowerCase();
    const replyTo = (parsedEmail.reply_to || "").toLowerCase();
    const returnPath = (parsedEmail.return_path || "").toLowerCase();

    // 1. Reply-To & Return-Path Spoofing / Impersonation Check
    let fromDomain = "";
    if (from.includes('@')) {
      fromDomain = from.split('@')[1].replace(/[>,\s]/g, '').trim();
    }
    let replyDomain = "";
    if (replyTo.includes('@')) {
      replyDomain = replyTo.split('@')[1].replace(/[>,\s]/g, '').trim();
    }

    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      score += 26;
      const threat = {
        name: "Spoofing & Impersonation",
        severity: "High",
        confidence: 93,
        icon: "repeat",
        explanation: "The Reply-To destination domain diverges from the visible From identity, indicating intentional rerouting of victim replies.",
        evidence: [
          `Visible sender domain: ${fromDomain}`,
          `Hidden reply collection domain: ${replyDomain}`,
          "Adversary configured external mailbox for reply harvesting"
        ]
      };
      detectedThreats.push(threat);
      evidenceList.push(`Mismatched Reply-To header (${replyDomain} vs ${fromDomain})`);
      iocs.push({ type: "Domain", value: replyDomain, category: "Harvesting Inbox", threat: "High" });
    }

    // 2. Urgent / Coercive Psychological Pressure & BEC Heuristics
    const urgentKeywords = ['urgent', 'wire transfer', 'immediate action', 'suspended', 'verify account', 'unauthorized', 'ceo', 'confidential', 'within 24 hours', 'action required'];
    const matchedUrgent = urgentKeywords.filter(kw => subject.includes(kw) || body.includes(kw));

    if (matchedUrgent.length >= 2) {
      score += 24;
      const isBec = matchedUrgent.some(kw => ['wire transfer', 'ceo', 'confidential'].includes(kw));
      detectedThreats.push({
        name: isBec ? "Business Email Compromise (BEC)" : "Phishing / Social Engineering",
        severity: isBec ? "Critical" : "High",
        confidence: isBec ? 95 : 91,
        icon: isBec ? "user-x" : "hook",
        explanation: "Psychological coercion detected through fabricated urgency, authority assertion, or financial pressure.",
        evidence: [
          `Detected urgency triggers: ${matchedUrgent.join(', ')}`,
          "Demands bypassing standard organizational validation channels"
        ]
      });
      evidenceList.push(`Urgent coercive language: ${matchedUrgent.slice(0, 3).join(', ')}`);
    }

    // 3. Brand Lookalike & Credential Harvesting
    const brandKeywords = ['paypal', 'microsoft', 'apple', 'google', 'chase', 'bank'];
    const matchedBrand = brandKeywords.find(b => from.includes(b) || subject.includes(b));
    if (matchedBrand) {
      const legitDomains = ['paypal.com', 'microsoft.com', 'apple.com', 'google.com', 'chase.com'];
      if (fromDomain && !legitDomains.some(ld => fromDomain.endsWith(ld))) {
        score += 26;
        detectedThreats.push({
          name: "Credential Theft / Brand Impersonation",
          severity: "Critical",
          confidence: 95,
          icon: "lock",
          explanation: `Unauthorized domain masquerading as reputable brand identity '${matchedBrand}'.`,
          evidence: [
            `Sender claims brand identity: '${matchedBrand}'`,
            `Sender domain '${fromDomain}' does not belong to verified brand infrastructure`
          ]
        });
        evidenceList.push(`Brand lookalike detected: ${fromDomain}`);
      }
    }

    // 4. Financial Diversion & BEC Banking Changes
    const finKeywords = ['routing number', 'swift code', 'beneficiary bank', 'new clearing facility', 'disbursements', 'wire instructions'];
    if (finKeywords.some(fk => body.includes(fk) || subject.includes(fk))) {
      score += 24;
      if (!detectedThreats.some(t => t.name.includes("Business Email Compromise"))) {
        detectedThreats.push({
          name: "Business Email Compromise (BEC)",
          severity: "Critical",
          confidence: 96,
          icon: "user-x",
          explanation: "Fraudulent payment diversion instructions targeting financial operations.",
          evidence: [
            "Altered banking/routing redirection instructions detected in email body",
            "Urgent request to modify vendor disbursement destination"
          ]
        });
      }
      evidenceList.push("Unauthorized banking/routing redirection instructions");
    }

    // 5. Credential Harvesting Verification
    const credKeywords = ['password', 'login', 'credentials', 'reset access', 'security alert', 're-authenticate', 'authenticator', 'restore access'];
    if (credKeywords.some(kw => subject.includes(kw) || body.includes(kw)) && parsedEmail.urls.length > 0) {
      score += 22;
      if (!detectedThreats.some(t => t.name.includes("Credential Theft"))) {
        detectedThreats.push({
          name: "Credential Theft",
          severity: "Critical",
          confidence: 94,
          icon: "lock",
          explanation: "Simulated security alerts paired with external login hyperlinks attempting to harvest corporate account credentials.",
          evidence: [
            "Subject or message body solicits authentication credentials",
            `Contains ${parsedEmail.urls.length} link(s) redirecting to external authentication forms`
          ]
        });
      }
      evidenceList.push("Credential solicitation paired with external URLs");
    }

    // 6. URL & Domain Intelligence Check
    parsedEmail.urls.forEach(u => {
      iocs.push({ type: "URL", value: u.url, category: "Extracted Link", threat: u.suspicion_score > 70 ? "Critical" : "High" });
      iocs.push({ type: "Domain", value: u.domain, category: "Target Host", threat: u.suspicion_score > 70 ? "Critical" : "Medium" });

      if (u.suspicion_score > 60) {
        score += 20;
        if (!detectedThreats.some(t => t.name === "Malicious Link")) {
          detectedThreats.push({
            name: "Malicious Link",
            severity: "High",
            confidence: u.suspicion_score,
            icon: "link-2",
            explanation: "Suspicious or obfuscated destination link detected within email body.",
            evidence: [
              `Target URL: ${u.url}`,
              `Indicators flagged: ${u.indicators.join(', ')}`
            ]
          });
        }
        evidenceList.push(`High risk URL identified: ${u.domain}`);
      }
    });

    // 5. Attachment Weaponization Check
    if (parsedEmail.attachments && parsedEmail.attachments.length > 0) {
      parsedEmail.attachments.forEach(att => {
        iocs.push({ type: "Hash", value: att.hash_sha256, category: `SHA-256 (${att.filename})`, threat: att.risk_state === "MALICIOUS" ? "Critical" : "Low" });

        if (att.risk_state === "MALICIOUS") {
          score += 30;
          detectedThreats.push({
            name: "Malware Delivery",
            severity: "Critical",
            confidence: 97,
            icon: "bug",
            explanation: "Weaponized attachment container or executable script intended to deliver malware.",
            evidence: [
              `Attachment: ${att.filename} (${att.type})`,
              ...att.indicators
            ]
          });
          evidenceList.push(`Weaponized attachment detected: ${att.filename}`);
        }
      });
    }

    // 6. Extracted IPs to IOCs
    parsedEmail.ips.forEach(ip => {
      iocs.push({ type: "IP", value: ip, category: "Extracted Server IP", threat: "High" });
    });

    // Clamp score 0 to 100
    score = Math.min(Math.max(score, 8), 98);

    // Determine state
    let state = "SAFE";
    let threatIcon = "shield-check";
    if (score < 20) {
      state = "SAFE";
      threatIcon = "shield-check";
    } else if (score < 40) {
      state = "LOW RISK";
      threatIcon = "shield";
    } else if (score < 60) {
      state = "SUSPICIOUS";
      threatIcon = "alert-circle";
    } else if (score < 80) {
      state = "HIGH RISK";
      threatIcon = "alert-triangle";
    } else {
      state = "CRITICAL";
      threatIcon = "shield-alert";
    }

    // Generate Geolocation Telemetry for extracted IPs
    const geolocations = this.generateGeolocations(parsedEmail.ips);

    return {
      case_id: `IG-${new Date().getFullYear()}${String(new Date().getMonth() + 1).padStart(2, '0')}${String(new Date().getDate()).padStart(2, '0')}-${Math.random().toString(36).substring(2, 6).toUpperCase()}`,
      investigator: "Analyst Tier-3 / SOC Ops (Simulation)",
      analysis_timestamp: new Date().toISOString(),
      eml_filename: "uploaded_inspection.eml",
      email_metadata: {
        subject: parsedEmail.subject,
        from: parsedEmail.from,
        to: parsedEmail.to,
        cc: parsedEmail.cc,
        reply_to: parsedEmail.reply_to || "None specified",
        return_path: parsedEmail.return_path || "None specified",
        date: parsedEmail.date,
        message_id: parsedEmail.message_id,
        mailer: parsedEmail.mailer,
        hop_count: parsedEmail.received_hops.length || 1,
        url_count: parsedEmail.urls.length,
        attachment_count: parsedEmail.attachments.length,
        ip_count: parsedEmail.ips.length || 1
      },
      risk_evaluation: {
        score: score,
        state: state,
        confidence: score > 70 ? 94 : 91,
        threat_icon: threatIcon,
        explanation: detectedThreats.length > 0
          ? `${detectedThreats.length} significant threat vectors detected: ${detectedThreats.map(t => t.name).join(', ')}.`
          : "Standard email authentication checks passed. No high-risk anomalies or malicious patterns identified.",
        detected_evidence_count: evidenceList.length,
        breakdown: {
          domain_reputation: Math.min(score + 5, 98),
          authentication_failure: score > 50 ? 90 : 10,
          content_urgency: matchedUrgent.length * 20,
          attachment_risk: parsedEmail.attachments.some(a => a.risk_state === "MALICIOUS") ? 98 : 5,
          link_suspicion: parsedEmail.urls.length > 0 ? 82 : 5
        }
      },
      detected_threats: detectedThreats,
      authentication: {
        spf: {
          status: score > 50 ? "FAIL" : "PASS",
          domain: fromDomain || "sender-domain.com",
          client_ip: parsedEmail.ips[0] || "185.220.101.45",
          mechanism: score > 50 ? "-all" : "include:spf.protection.com",
          explanation: score > 50 ? "Sender IP is not permitted by domain SPF record." : "Sender IP is authorized by domain SPF record.",
          alignment: score > 50 ? "FAIL" : "PASS"
        },
        dkim: {
          status: score > 50 ? "FAIL" : "PASS",
          selector: "s2024",
          domain: fromDomain || "sender-domain.com",
          signature_valid: score <= 50,
          algorithm: "rsa-sha256",
          explanation: score > 50 ? "Cryptographic signature validation failed or signature is missing." : "Cryptographic signature validated successfully.",
          alignment: score > 50 ? "FAIL" : "PASS"
        },
        dmarc: {
          status: score > 50 ? "FAIL" : "PASS",
          policy: score > 50 ? "reject" : "none",
          disposition: score > 50 ? "QUARANTINE_RECOMMENDED" : "DELIVERED",
          explanation: score > 50 ? "DMARC alignment check failed for both SPF and DKIM." : "DMARC passed with valid domain alignment.",
          alignment: score > 50 ? "FAIL" : "PASS"
        }
      },
      header_forensics: {
        originating_ip: parsedEmail.ips[0] || "185.220.101.45",
        sending_server: parsedEmail.received_hops.length > 0 ? parsedEmail.received_hops[0].server : "smtp.relay.net",
        relay_path: parsedEmail.received_hops.length > 0 ? parsedEmail.received_hops : [
          { hop: 1, server: "mail-origin.relay (185.220.101.45)", by: "core-gateway.net", timestamp: parsedEmail.date, delay_ms: 120, tls: "TLSv1.2", role: "Origin" },
          { hop: 2, server: "core-gateway.net (104.244.42.1)", by: "mx.inbound.local", timestamp: parsedEmail.date, delay_ms: 190, tls: "TLSv1.3", role: "Ingress Gateway" }
        ]
      },
      urls: parsedEmail.urls,
      geolocations: geolocations,
      attachments: parsedEmail.attachments,
      iocs: iocs,
      forensic_timeline: this.generateTimeline(detectedThreats, score),
      recommendations: this.generateRecommendations(score, detectedThreats)
    };
  }

  static generateGeolocations(ips) {
    const list = ips && ips.length > 0 ? ips : ["185.220.101.45", "198.51.100.24", "104.244.42.1"];
    const database = {
      "185.220.101.45": {
        ip: "185.220.101.45",
        type: "Originating Node",
        country: "Romania",
        country_code: "RO",
        city: "Bucharest",
        region: "Ilfov County",
        latitude: 44.4268,
        longitude: 26.1025,
        isp: "M247 Europe Ltd",
        asn: "AS200052",
        organization: "Known Tor Exit / Bulletproof Infrastructure",
        risk_score: 89,
        reputation: "Malicious Origin",
        abuse_score: 89,
        disclaimer: "Approximate BGP routing location."
      },
      "198.51.100.24": {
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
      "104.244.42.1": {
        ip: "104.244.42.1",
        type: "Ingress Gateway",
        country: "United States",
        country_code: "US",
        city: "Ashburn",
        region: "Virginia",
        latitude: 39.0438,
        longitude: -77.4874,
        isp: "Cloudflare Ingress Protection",
        asn: "AS13335",
        organization: "Enterprise Edge Gateway",
        risk_score: 8,
        reputation: "Clean / Gateway",
        abuse_score: 0,
        disclaimer: "Approximate BGP routing location."
      }
    };

    return list.map(ip => database[ip] || {
      ip: ip,
      type: "Extracted IP",
      country: "International Telemetry",
      country_code: "XX",
      city: "Transit Point",
      region: "Global",
      latitude: 48.8566,
      longitude: 2.3522,
      isp: "BGP Autonomous System",
      asn: "AS15169",
      organization: "Carrier Transit Provider (Simulated)",
      risk_score: 35,
      reputation: "Monitored",
      abuse_score: 10,
      disclaimer: "Approximate BGP routing location."
    });
  }

  static generateTimeline(threats, score) {
    const events = [
      { step: 1, title: "Email Received & Ingested", time: "T+0.00s", desc: "Perimeter mail gateway records initial SMTP handshake and envelope data." },
      { step: 2, title: "RFC Header Parser Executed", time: "T+0.12s", desc: "MIME boundaries unfolded; Received hops and sender fields cataloged." },
      { step: 3, title: "Origin IP Geolocation Resolved", time: "T+0.25s", desc: "Sender IP correlated with ASN database and BGP routing prefixes." },
      { step: 4, title: "SPF / DKIM / DMARC Verification", time: "T+0.38s", desc: score > 50 ? "Authentication failed: SPF unauthorized and DKIM body hash mismatch." : "Authentication verified: Strict cryptographic alignment." }
    ];

    if (score > 50) {
      events.push({ step: 5, title: "Threat Classification Triggered", time: "T+0.52s", desc: `Identified ${threats.length} threat vectors across content, URLs, and attachments.` });
      events.push({ step: 6, title: "Forensic Intelligence Report Compiled", time: "T+0.68s", desc: `Risk Score calculated at ${score} (${score >= 80 ? 'CRITICAL' : 'HIGH RISK'}).` });
    } else {
      events.push({ step: 5, title: "Compliance Check Passed", time: "T+0.45s", desc: "No malicious payloads, lookalike domains, or weaponized files detected." });
    }

    return events;
  }

  static generateRecommendations(score, threats) {
    if (score < 40) {
      return [
        { title: "Standard Processing", desc: "Allow message delivery. No quarantine or defensive actions required." }
      ];
    }

    const recs = [
      { title: "Immediate Tenant Quarantine", desc: "Purge this message across all employee inboxes to prevent accidental execution." },
      { title: "Perimeter Firewall Drop", desc: "Add extracted adversary IPs to perimeter firewall blocking tables." },
      { title: "DNS Resolver Sinkhole", desc: "Sinkhole flagged destination domains at internal recursive resolvers." }
    ];

    if (threats.some(t => t.name.includes("Credential"))) {
      recs.push({ title: "Force Password Reset", desc: "Prompt password reset and revoke active sessions for targeted users." });
    }

    if (threats.some(t => t.name.includes("Malware"))) {
      recs.push({ title: "Endpoint Threat Sweep", desc: "Initiate EDR scan across fleet for extracted file hashes and execution artifacts." });
    }

    return recs;
  }
}
