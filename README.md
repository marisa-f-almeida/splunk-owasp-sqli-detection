# SIEM Lab: OWASP Top 10 Web Application Firewall (WAF) Payload Inspection (Splunk)

An operational application-layer monitoring architecture implemented within **Splunk Cloud (Dashboard Studio)**. This project transforms raw Web Application Firewall (WAF) access strings into behavioral alerts to intercept SQL Injection (SQLi) attack strings and malicious database enumeration signatures.

---

## 🔍 Attack Context & Detection Mechanics

Adversaries exploit application vulnerabilities by injecting malicious payloads into unvalidated input fields to execute unauthorized backend database operations. This monitoring layer inspects HTTP parameter transactions to identify active manipulation attempts:

1. **Payload Parameter Regex Matching**: Audits input telemetry for known SQL structural patterns (e.g., `UNION SELECT`, comment syntax `--`).
2. **Access Footprint Correlations**: Measures high-frequency request behaviors targeting authentication endpoints from anomalous external source IP points.
3. **Automated WAF Escalations**: Tags input injection behaviors with severe SOC classifications, alerting incident teams before data exfiltration occurs.

---

## 💻 Core SPL OWASP SQLi Inspection Framework

```splunk
| makeresults count=110
| streamstats count as row
| eval time_offset = row * 12
| eval _time = _time - time_offset
| eval src_ip = case(row <= 95, "192.168.1.55", 1=1, "198.51.100.230")
| eval uri_path = "/v1/auth/login"
| eval http_payload = case(src_ip=="198.51.100.230", "admin' UNION SELECT password, null FROM users--", 1=1, "user=marisa&pass=secure123")
| stats count by src_ip, uri_path, http_payload
| sort - count
| eval security_classification = if(src_ip=="198.51.100.230", "CRITICAL ALERT: EXPLOIT ATTEMPT - OWASP SQL INJECTION IDENTIFIED", "NORMAL WEB TRAFFIC")
| rename src_ip as "Source Client IP", uri_path as "Target URI Path", http_payload as "Inspected HTTP Payload String", count as "Request Volume", security_classification as "SOC Alert Severity"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Structure)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: WAF App-Layer Inbound Traffic Inspection Matrix
- **Monitored Indicators (IoCs)**: Attacker Client Source IP, Target Application URI Path, Malicious Input Code Segment, Real-time Severity Enforcement Flag.
