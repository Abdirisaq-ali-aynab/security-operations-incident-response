# 🛡️ Security Operations – AI-Assisted Incident Response

## Overview
This project simulates a real-world security incident affecting a Windows endpoint and demonstrates how a Security Operations team manages the incident lifecycle end to end. The focus is on incident triage, investigation, containment, operational decision-making, and post-incident improvement. Model Context Protocol (MCP) was leveraged to enhance investigation efficiency while maintaining analyst-driven validation and control.

---

## 🚨 Incident Scenario
A high-severity alert indicated suspicious activity on a Windows workstation, suggesting potential malware execution and persistence. Initial assessment identified risk of credential exposure, lateral movement, and business disruption if not contained promptly.
  
---

## 🔍 Security Operations Workflow

### Detection & Triage
- Validated alert fidelity and assessed scope and potential organizational impact.
- Determined incident severity and response priority.

### Investigation
- Analyzed endpoint processes, persistence mechanisms, registry modifications, and event logs.  
- Used AI-assisted Model Context Protocol (MCP) tooling to accelerate analysis while validating findings through manual review.

### Containment
- Recommended endpoint isolation and credential hygiene actions to prevent further compromise. 
- Identified remediation steps aligned with security operations best practices.

### Eradication & Recovery
- Verified removal of malicious artifacts and confirmed system stability.  
- Ensured monitoring was in place to detect recurrence.

### Post-Incident Review
- Identified control gaps and recommended preventive improvements.
- Documented lessons learned to improve future response efficiency.
  
---

## 🧰 Tools & Technologies
- Windows Event Logs  
- Sysinternals Suite  
- SIEM concepts  
- MCP AI-assisted analysis tools  
- MITRE ATT&CK Framework  

---

## 📊 Operational & Business Impact
This incident response exercise demonstrated how structured workflows reduce response time, improve consistency, and limit organizational risk. The investigation highlighted the importance of endpoint visibility, credential protection, and documented response procedures within Security Operations.


---

## Response Metrics
- **Mean Time to Detection (MTTD):** ~30 minutes  
- **Mean Time to Containment (MTTC):** ~1 hour  
- **Mean Time to Remediation (MTTR):** ~2 hours  

---

## Escalation & Communication
- Incident escalated to Security Operations leadership due to high severity  
- Status and findings communicated to IT and management stakeholders  
- Incident documentation prepared for post-incident review

---

## Incident Response Playbook Snippet
- If alert severity is **High**, escalate to Security Operations lead  
- If credential exposure is suspected, initiate credential hygiene actions  
- If lateral movement is suspected, isolate affected endpoint immediately  
- Document all actions taken and maintain timeline of events



## 📄 Deliverables
- Incident investigation notes  
- Indicators of Compromise (IOCs)  
- Incident response checklist  
- Management-level incident summary  

---
### Investigation Summary
A detailed technical investigation was conducted to validate malicious activity, identify persistence mechanisms, and confirm incident scope.

- [Full Technical Investigation Report](investigation/investigation-report.md)


## Key Takeaways (Security Operations Focus)
- Applied structured incident response processes aligned with Security Operations practices  
- Translated technical findings into operational and business risk 
- Demonstrated documentation discipline and response repeatability  
- Showcased responsible use of AI to support analyst decision-making


## Lessons Learned
- Broader endpoint monitoring can reduce detection gaps  
- Tuning alerts for false positives improves operational efficiency  
- Manual validation remains crucial despite tool assistance


