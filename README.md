# SIEM Lab: Web WAF Logs & SQL Injection (SQLi) Anomaly Detection (Splunk)

An enterprise application-layer security monitoring framework implemented within **Splunk Cloud (Dashboard Studio)**. This project engineers custom query extraction models to identify patterns matching **SQL Injection (SQLi)** exploits and automated web application vulnerability scanning targeting public-facing web entry points.

---

## 🔍 Attack Context & Detection Logic

Web applications are highly targeted perimeter vectors. Attackers utilize malicious query parameters inside HTTP string payloads to trick application backends into running unintended command routines. This analytical pipeline acts as a Web Application Firewall (WAF) rule to intercept signatures before data breach occurrences:

1. **URI Payload Parsing**: Scans inbound HTTP URI strings for characteristic metadata query components containing malicious database syntax markers (`UNION SELECT`, `OR 1=1`, `--`).
2. **Volumetric Request Frequency**: Monitors the execution speed of requests coming from external hosts attempting to brute-force parameter fields.
3. **Automated Risk Escalation**: Flags an external IP address as an active threat vector if its payload signatures cross defined string length anomalies.

---

## 💻 Core SPL Application Threat Detection Framework

```splunk
| makeresults count=80
| streamstats count as row
| eval time_offset = row * 4
| eval _time = _time - time_offset
| eval src_ip = case(row <= 15, "203.0.113.5", row <= 70, "45.89.23.200", 1=1, "192.168.1.55")
| eval http_method = "POST"
| eval uri_path = "/api/v1/auth/login"
| eval uri_query = case(src_ip=="45.89.23.200", "user=' UNION SELECT null, username, password FROM users--", src_ip=="203.0.113.5", "user=' OR '1'='1", 1=1, "user=ana.silva")
| eval http_status = case(src_ip=="192.168.1.55", "200", 1=1, "500")
| stats count as total_requests, values(uri_query) as sampled_payloads by src_ip, http_method, uri_path, http_status

| eval is_sqli_signature = if(match(sampled_payloads, "(?i)UNION|SELECT|OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"), "MATCHED SQLi ATTACK SIGNATURE", "SAFE TRAFFIC")
| where is_sqli_signature == "MATCHED SQLi ATTACK SIGNATURE"
| eval soc_remediation_priority = "CRITICAL ALERT: TRIGGERING AUTOMATED WAF BOUNDARY BLOCK"
| rename src_ip as "Attacker IP", http_method as "HTTP Method", uri_path as "Target URI Path", total_requests as "Exploit Attempts Count", sampled_payloads as "Intercepted Payload", soc_remediation_priority as "SOC Remediation Action"
```

---

## 📊 Dashboard Engineering Details

- **Visual Dashboard Mode**: Dashboard Studio (Grid Layout Structure)
- **Primary Interface Theme**: SOC Dark Operational Standard
- **Core Visual Element**: WAF Application Layer Incident Analysis Grid
- **Monitored Indicators (IoCs)**: Attacker Public IP, Inbound Malicious HTTP String Input, Target Web Component Endpoint, Automated Firewall Block Trigger.
