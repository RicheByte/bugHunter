# Security & Safety Guide - CVE Automation Framework v4.2

## 🛡️ Safety-First Architecture

Version 4.2 introduces comprehensive safety controls to prevent unauthorized or accidental security testing. This framework is designed for **authorized security professionals only**.

---

## ⚠️ CRITICAL: Before You Begin

### Legal Requirements
1. ✅ **Obtain written authorization** from system owners
2. ✅ **Create a signed Rules of Engagement (RoE)** document
3. ✅ **Understand local laws** regarding security testing
4. ✅ **Never test systems you don't own or have authorization for**

### Ethical Use
This tool is for:
- Authorized penetration testing
- Vulnerability assessments with permission
- Security research in controlled environments
- Educational purposes with explicit consent

This tool is **NOT** for:
- Unauthorized access attempts
- Malicious hacking
- Testing third-party systems without permission
- Any illegal activities

---

## 🔐 Operational Modes

### 1. PROBE Mode (Default - SAFE)
**Risk Level:** ✅ Low  
**RoE Required:** ❌ No  
**Description:** Passive reconnaissance only

**What it does:**
- Fingerprints web servers, CMS, technologies
- Detects error signatures (SQL, command injection indicators)
- Time-based detection (non-invasive)
- Banner grabbing
- WAF detection

**What it doesn't do:**
- NO active exploitation
- NO payload delivery
- NO authentication bypass attempts
- NO data modification

**Example:**
```bash
python cve.py --mode probe --targets example.com
```

### 2. SCAN Mode (Active Testing)
**Risk Level:** ⚠️ Medium  
**RoE Required:** ✅ **YES - MANDATORY**  
**Description:** Active vulnerability scanning

**What it does:**
- Everything in PROBE mode, plus:
- Active vulnerability detection
- Non-destructive exploitation attempts
- Authentication testing
- Input validation checks

**What it doesn't do:**
- NO data exfiltration
- NO persistent changes
- Limited to read-only operations

**Example:**
```bash
python cve.py --mode scan --roe rules_of_engagement.json --targets authorized-target.com
```

### 3. EXPLOIT Mode (Destructive Testing)
**Risk Level:** 🚨 High  
**RoE Required:** ✅ **YES - MANDATORY + Explicit Authorization**  
**Description:** Full exploitation capabilities

**What it does:**
- Everything in SCAN mode, plus:
- Active exploitation with payload delivery
- Session establishment
- Command execution
- Authentication bypass

**WARNING:** This mode can:
- Modify data
- Execute commands on target systems
- Establish sessions
- Trigger security alerts

**Example:**
```bash
python cve.py --mode exploit --roe rules_of_engagement.json --enable-evasion --targets authorized-target.com
```

---

## 📝 Rules of Engagement (RoE)

### Creating RoE

1. **Generate Template:**
```bash
python cve.py --generate-roe-template
```

2. **Customize the RoE:**
Edit `rules_of_engagement_template.json`:
- Fill in authorization details
- Define target scope (included/excluded)
- Set time windows
- Specify allowed modes
- Get approval signatures

3. **Sign the RoE:**
```powershell
# Set signing key (store securely!)
$env:ROE_SIGNING_KEY = "your-256-bit-secret-key-here"

# Framework will auto-generate HMAC on first use
python cve.py --mode scan --roe rules_of_engagement.json --targets test.example.com
```

### RoE Validation

The framework validates:
- ✅ HMAC signature authenticity
- ✅ Approval status
- ✅ Target authorization
- ✅ Time window compliance
- ✅ Mode authorization
- ✅ Expiration dates

**If validation fails, the framework will NOT run.**

---

## 🔒 Security Features

### 1. Credential Security
- **Algorithm:** PBKDF2HMAC with SHA-256
- **Iterations:** 480,000 (OWASP 2023 recommendation)
- **Salt:** Random 256-bit salt per installation
- **Storage:** AES-256 encrypted with Fernet
- **File Permissions:** 0600 (owner read/write only)

**Setup:**
```powershell
$env:CVE_MASTER_PASSWORD = "your-strong-password-here"
python cve.py --targets example.com
```

### 2. Audit Logging
- **Format:** Append-only JSONL
- **Integrity:** HMAC-SHA256 signature per entry
- **Chain:** Each entry includes previous entry's hash
- **Tamper Detection:** Automatic on read
- **Rotation:** Automatic at 100MB

**Verify Integrity:**
```bash
python cve.py --verify-audit-log
```

**Audit Log Contents:**
- All framework operations
- Target authorization checks
- Vulnerability detections
- Mode changes
- RoE validation events

### 3. ML Advisory System

**Important:** ML predictions are **ADVISORY ONLY**

- ✅ ML suggests possible false positives
- ✅ All results retained for human review
- ❌ ML does NOT filter out findings
- ❌ Human review is REQUIRED

**Rationale:**
- Prevents missed vulnerabilities
- Maintains compliance
- Ensures accountability

---

## 🚦 Circuit Breaker & Rate Limiting

### Per-Target Circuit Breaker
**Protects against cascade failures:**
- Opens after 5 consecutive failures
- Blocks requests for 60 seconds
- Tests recovery with half-open state
- Closes after 2 successful attempts

### Adaptive Rate Limiting
**Prevents detection and server overload:**
- Default: 10 requests/second
- Adaptive: Adjusts based on success/failure
- Burst support: Up to 20 concurrent requests
- Jitter: Random delays to avoid patterns

---

## 📊 Compliance & Reporting

### Supported Frameworks
1. NIST Cybersecurity Framework
2. PCI DSS v4.0
3. ISO/IEC 27001:2022
4. CIS Controls v8
5. OWASP Top 10:2021

### Audit Trail
All operations logged to:
- `audit.jsonl` - HMAC-signed audit log
- `cve_framework.log` - Standard application log
- Reports in `reports/` directory

### Log Retention
- **Audit Log:** 10,000 entries (auto-rotating)
- **Application Log:** Configurable
- **Reports:** Permanent (until manual deletion)

---

## 🎯 Best Practices

### 1. Start with Probe Mode
Always begin assessments in probe mode:
```bash
python cve.py --mode probe --targets test-environment.local
```

### 2. Validate RoE Before Active Testing
```bash
# Dry run - validates RoE without scanning
python cve.py --mode scan --roe roe.json --health-check
```

### 3. Use Time Windows
Configure testing during off-hours:
```json
"time_windows": [{
  "start": "22:00",
  "end": "06:00",
  "timezone": "UTC"
}]
```

### 4. Monitor Audit Logs
Regularly verify log integrity:
```bash
python cve.py --verify-audit-log
```

### 5. Review ML Advisories
Check all ML-flagged findings:
```bash
# Search for ML advisories
python cve.py --mode scan --targets example.com | grep "ML Advisory"
```

### 6. Limit Scope
Start small and expand:
```json
"included_targets": [
  "single-test-server.example.com"
]
```

---

## 🚨 Emergency Procedures

### If Unauthorized Activity Detected
1. **STOP IMMEDIATELY:**
```bash
Ctrl+C  # Terminates framework
```

2. **Check Audit Log:**
```bash
python cve.py --verify-audit-log
```

3. **Contact Security Team:**
Refer to RoE emergency contacts

### If Production Impact Occurs
1. **STOP ALL TESTING**
2. **Notify system owners immediately**
3. **Document incident in audit log**
4. **Provide incident report**

### If RoE Expires Mid-Scan
- Framework automatically terminates
- All progress logged to audit
- Resume only after RoE renewal

---

## 📖 Configuration Reference

### Safe Defaults (framework_config.json)
```json
{
  "execution": {
    "mode": "probe",
    "max_workers": 20,
    "requests_per_second": 10
  },
  "security": {
    "enable_evasion": false,
    "require_roe": true
  },
  "logging": {
    "enable_audit_log": true,
    "audit_log_file": "audit.jsonl"
  }
}
```

### Override (Use Carefully)
```json
{
  "security": {
    "enable_evasion": true,   // Requires RoE
    "require_roe": true        // NEVER set to false
  }
}
```

---

## 🔍 Troubleshooting

### "RoE validation failed"
1. Check RoE file exists
2. Verify HMAC signature
3. Confirm approval status
4. Check expiration date
5. Validate target scope

### "Target not authorized"
- Add target to `included_targets` in RoE
- Remove from `excluded_targets`
- Verify network range includes target

### "Outside time window"
- Check current time vs RoE time windows
- Verify timezone settings
- Adjust schedule or wait for window

### "Invalid mode"
- Verify mode is in RoE `allowed_modes`
- Check if mode requires RoE (scan/exploit)
- Confirm approval for requested mode

---

## 📞 Support & Reporting

### Security Issues
**DO NOT** use this framework for malicious purposes.

If you discover a security issue **in the framework itself**:
1. Do NOT exploit it
2. Report responsibly
3. Contact: security@framework-project.example

### Questions
- Documentation: README_v4.2.md
- Quick Start: QUICKSTART_v4.2.md
- Installation: INSTALLATION_v4.2.md

---

## ⚖️ Legal Disclaimer

**This framework is provided for authorized security testing only.**

By using this tool, you agree:
1. You have explicit authorization for all testing
2. You understand applicable laws and regulations
3. You accept full responsibility for your actions
4. You will use this tool ethically and legally

**The authors and contributors are NOT responsible for misuse of this tool.**

---

## 📜 Version History

- **v4.2 (2025-01-24):** Safety-First Edition
  - RoE system
  - HMAC audit logging
  - Safe defaults (probe mode)
  - ML advisory mode
  - Circuit breaker

- **v4.1 (2025-01-23):** Enterprise Edition
  - ML features
  - Compliance mapping
  - Enterprise integrations

- **v4.0 (2025-01-22):** Initial Release
  - Core CVE automation
  - Basic exploit modules

---

**Remember: With great power comes great responsibility. Test ethically.**
