# 🔒 Technical Incident Response Report: Windows Host Compromise


---

**Key Findings:**
- Windows Defender and UAC were systematically disabled
- Fileless .NET payload executed in-memory using XOR encryption
- AnyDesk remote access tool installed for persistent access
- Active C2 communication to external infrastructure
- Multiple persistence mechanisms established

**Risk Level:** 🔴 **CRITICAL**

---

## 🎯 Attack Overview

### Attack Chain Summary

| Stage | Technique | Component | MITRE ATT&CK |
|-------|-----------|-----------|--------------|
| **1** | Defense Evasion | `anz.ps1` | T1562.001 |
| **2** | Discovery | `kor.bat` | T1087, T1018 |
| **3** | Execution | `tyvm87.dat` | T1059.001 |
| **4** | Persistence | `AnyDesk.exe` | T1543.003 |

### Threat Actor Profile
- **Sophistication:** Intermediate to Advanced
- **Tactics:** Multi-stage attack with defense evasion
- **Tools:** Custom scripts + legitimate remote access software
- **Objective:** Persistent remote access and potential data exfiltration

---

## ⏰ Timeline of Events (UTC)

```
17:30 → Defense Evasion Phase
        ├─ PowerShell execution: anz.ps1
        ├─ Disabled Windows Defender real-time protection
        └─ Modified registry: DisableAntiSpyware = 1

17:33 → Reconnaissance Phase
        ├─ Batch script execution: kor.bat
        ├─ Enumerated local users and administrators
        ├─ Collected network configuration
        └─ Listed running processes and services

18:17 → Payload Deployment Phase
        ├─ XOR-encrypted .NET assembly loaded
        ├─ Fileless execution via PowerShell
        └─ In-memory reflective loading

18:26 → Persistence Establishment
        ├─ AnyDesk installation to C:\ProgramData\
        ├─ Service creation (auto-start)
        ├─ Scheduled task creation
        └─ Startup shortcut placed
```

---

## 🧩 Technical Analysis

### Stage 1: Defense Evasion (`anz.ps1`)

**Purpose:** Disable security controls to enable subsequent attack stages

**Key Actions:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
```

**Impact:**
- Real-time malware scanning disabled
- Behavior-based detection disabled
- UAC protections weakened
- Exclusion paths added for malware directories

**Registry Modifications:**
- `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` = 1

---

### Stage 2: Reconnaissance (`kor.bat`)

**Purpose:** Gather system and network intelligence

**Commands Executed:**
```batch
net user
net localgroup administrators
ipconfig /all
tasklist
systeminfo
```

**Intelligence Collected:**
- Local user accounts and group memberships
- Network adapter configurations and IP addressing
- Running processes and services
- System specifications and patch level

---

### Stage 3: Fileless Payload (`tyvm87.dat`)

**Technical Details:**
- **File Size:** 34 KB
- **Encryption:** XOR cipher with key `0xAA`
- **Type:** .NET assembly loader
- **Execution Method:** PowerShell reflective loading
- **Location:** `C:\Users\Administrator\AppData\Roaming\tyvm87.dat`

**Analysis:**
- Payload remained fileless in memory after initial load
- Leveraged PowerShell for .NET assembly reflection
- Evaded traditional file-based detection mechanisms
- XOR decryption performed at runtime

**Decryption Logic:**
```
for each byte in file:
    decrypted_byte = byte XOR 0xAA
```

---

### Stage 4: Backdoor Installation (`AnyDesk.exe`)

**File Information:**
- **SHA256:** `D2A7B55FD4A1114751F1FCD2B55366D37E5DAB9621F2C5428EC95997E57878A1`
- **Path:** `C:\ProgramData\AnyDesk\AnyDesk.exe`
- **Service Name:** AnyDesk
- **Start Type:** Automatic

**Persistence Mechanisms:**
1. **Windows Service:** Configured to start automatically with SYSTEM privileges
2. **Scheduled Task:** `\WinInputService` running under SYSTEM context
3. **Startup Shortcut:** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AnyDesk.lnk`

**Network Activity:**
- **External C2:** `64.31.23.26` (relay-6a630189.net.anydesk.com) on port 443
- **Suspicious Internal Connection:** `10.1.145.123:443` via svchost.exe

---

## 🚨 Indicators of Compromise (IOCs)

### File Artifacts

| File Path | Description 
|-----------|-------------
| `C:\Users\Administrator\AppData\Local\anz.ps1` | Defense evasion script  | 
| `C:\Users\Administrator\AppData\Local\kor.bat` | Reconnaissance script  |
| `C:\Users\Administrator\AppData\Roaming\tyvm87.dat` | Encrypted payload | 
| `C:\ProgramData\AnyDesk\AnyDesk.exe` | Remote access backdoor | 
| `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\AnyDesk.lnk` | Persistence shortcut | 

### Network Indicators

```
External C2 Infrastructure:
├─ IP: 64.31.23.26
├─ Domain: relay-6a630189.net.anydesk.com
└─ Port: 443 (HTTPS)

Suspicious Internal Communication:
├─ IP: 10.1.145.123
├─ Port: 443
└─ Process: svchost.exe
```

### Registry Indicators

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware = 1
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\AnyDesk
HKLM\SYSTEM\CurrentControlSet\Services\AnyDesk
```

### Scheduled Tasks

```
Task Name: \WinInputService
User Context: SYSTEM
Trigger: At system startup
Action: Execute AnyDesk.exe
```

---

## 📊 Impact Assessment

| Category | Severity | Details |
|----------|----------|---------|
| **Security Controls** | 🔴 Critical | Windows Defender and UAC completely disabled |
| **Confidentiality** | 🔴 Critical | Remote access established; data exfiltration possible |
| **Integrity** | 🔴 Critical | System configuration modified; unauthorized software installed |
| **Availability** | 🟡 Medium | No destructive actions observed; system remained operational |
| **Credential Exposure** | 🔴 Critical | Administrator credentials potentially compromised |

**Overall Risk Score:** 9.2/10 (Critical)

---

## 🛡️ Containment & Remediation

### Immediate Actions (Completed)

✅ **Network Isolation**
- Host `win2.mcp.lab` disconnected from network
- Firewall rules applied to block outbound C2 communication

✅ **Service Termination**
- AnyDesk service stopped and disabled
- Malicious scheduled task `\WinInputService` deleted

✅ **Artifact Quarantine**
- All malicious files moved to quarantine directory
- Evidence preserved for forensic analysis

### Recommended Recovery Steps

1. **Credential Reset**
   - Force password reset for all local accounts
   - Reset domain credentials if domain-joined
   - Invalidate any active sessions

2. **System Rebuild**
   - Perform clean OS reinstallation from trusted media
   - Apply all security patches before network reconnection
   - Restore data from pre-compromise backups

3. **Security Hardening**
   - Re-enable and configure Windows Defender
   - Implement application whitelisting
   - Enable PowerShell script block logging
   - Configure Sysmon for enhanced monitoring

4. **Network Monitoring**
   - Hunt for IOCs across enterprise network
   - Monitor for C2 IP addresses (64.31.23.26, 10.1.145.123)
   - Review firewall logs for similar patterns

---

## 🔬 Evidence Collection

All malicious artifacts were collected and are available for further analysis:

| Evidence File | Size | Collection URL |
|---------------|------|----------------|
| `1761872376_tyvm87.dat` | 34 KB | `http://medic.mcp.lab:8000/collections/1761872376_tyvm87.dat` |
| `1761873478_anz.ps1` | 759 B | `http://medic.mcp.lab:8000/collections/1761873478_anz.ps1` |
| `1761873482_kor.bat` | 670 B | `http://medic.mcp.lab:8000/collections/1761873482_kor.bat` |
| `1761872389_init.vbs` | 178 B | `http://medic.mcp.lab:8000/collections/1761872389_init.vbs` |
| `1761872501_EnableClearType.ps1` | 656 B | `http://medic.mcp.lab:8000/collections/1761872501_EnableClearType.ps1` |

**Chain of Custody:** All evidence collected and stored following standard forensic procedures.

---

## 📈 Confidence Assessment

| Finding | Confidence Level | Reasoning |
|---------|------------------|-----------|
| Host compromised | 99% | Multiple malicious artifacts confirmed |
| Multi-stage attack | 99% | Clear progression through attack chain |
| Defender disabled | 97% | PowerShell commands and registry keys verified |
| Active C2 connection | 90% | Network traffic to known AnyDesk infrastructure |
| Fileless execution | 98% | Memory analysis confirms reflective loading |
| Unauthorized remote access | 90% | AnyDesk installation without legitimate justification |

**Overall Confidence:** 99% - Near Certainty

---

## 🎓 Learning Outcomes

This capstone exercise demonstrated practical skills in:

- **Malware Analysis:** Identifying and analyzing multi-stage attack components
- **Forensic Investigation:** Systematic evidence collection and documentation
- **Threat Intelligence:** IOC extraction and MITRE ATT&CK framework mapping
- **Incident Response:** Containment, remediation, and recovery planning
- **Technical Documentation:** Professional report writing for executive and technical audiences

### Tools & Technologies Used
- MCP Medic Triage Platform
- PowerShell script analysis
- XOR encryption/decryption techniques
- Windows registry forensics
- Network traffic analysis
- MITRE ATT&CK framework

---

## 📚 References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [NIST Incident Response Guide (SP 800-61)](https://www.nist.gov/privacy-framework/nist-sp-800-61)
- [SANS Incident Handler's Handbook](https://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901)
