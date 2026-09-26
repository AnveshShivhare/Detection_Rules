# Detection Rules

Vendor-neutral Sigma detection rules for Windows endpoint threats, mapped to MITRE ATT&CK.
Rules are written against Sysmon and Windows Security event logs and validated using sigma-cli.

---

## Rules

| Rule | ATT&CK Tactic | Technique | Severity | Log Source |
|---|---|---|---|---|
| [Mimikatz LSASS Memory Access](./mimikatz_lsass_access.yml) | Credential Access (TA0006) | T1003.001 | High | Sysmon EID 10 |
| [Malicious PowerShell Stager](./Malicious_PowerShell_Stager_Payload.yml) | Execution (TA0002), Defense Evasion (TA0005) | T1059.001, T1027 | High | Sysmon EID 1 |
| [Multiple Failed Network Logons](./Bruteforce_attack.yml) | Credential Access (TA0006) | T1110 | Medium | Windows Security EID 4625 |

---

## Environment Requirements

Rules are authored for Windows endpoints with the following logging enabled:

- **Sysmon** — Process Creation (EID 1), Process Access (EID 10)
  Recommended config: [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- **Windows Security Logging** — Audit Logon Failures (EID 4625)
  Logon type 3 (Network) must be audited

---

## Usage

### Prerequisites

```bash
pip3 install sigma-cli
sigma plugin install splunk
sigma plugin install sysmon   # process pipeline
```

### Convert to Splunk SPL

```bash
# Single rule
sigma convert -t splunk -p sysmon -p splunk_windows ./mimikatz_lsass_access.yml

# All rules
sigma convert -t splunk -p sysmon -p splunk_windows ./*.yml
```

### Convert to Microsoft Sentinel KQL

```bash
sigma convert -t microsoft365defender -p sysmon ./*.yml
```

---

## Rule Notes

### Mimikatz LSASS Memory Access
Detects process access to `lsass.exe` with GrantedAccess values associated with credential
material extraction. Legitimate security tools (AV, EDR agents) may also access LSASS —
review `SourceImage` and `CallTrace` fields to triage. Unsigned modules in CallTrace
significantly raise confidence of malicious activity.

Validated GrantedAccess values: `0x1010`, `0x1038`, `0x143a`, `0x1fffff`

### Malicious PowerShell Stager
Detects PowerShell launched with Base64-encoded command arguments, a common initial execution
pattern in phishing and fileless malware delivery. High-fidelity variant: filter
`ParentImage` for Office applications — PowerShell spawned from WINWORD.exe or EXCEL.exe
indicates macro-based execution and warrants immediate escalation.

### Multiple Failed Network Logons
Base rule detecting individual network logon failures (Logon Type 3). Brute force
identification requires threshold correlation at the SIEM layer: group by `IpAddress` and
`TargetUserName` over a 5-minute window, alert on count ≥ 5. Sigma correlation rule
forthcoming.

---

## Lab Environment

Rules developed and validated in a homelab SOC environment:

- **SIEM**: Splunk Enterprise (free license) + Wazuh
- **Endpoint**: Windows 10 with Sysmon (SwiftOnSecurity config) + Configured to detect EventCode: 10 for lsass.exe access
- **Log forwarding**: Splunk Universal Forwarder
- **Attack simulation**: Mimikatz, encoded PowerShell payloads, manual brute force

---

## Author

**Anvesh Shivhare**
M.Tech Cyber Security — National Forensic Sciences University (NFSU), Gandhinagar
[LinkedIn](https://linkedin.com/in/anveshshivhare) · [GitHub](https://github.com/AnveshShivhare)
