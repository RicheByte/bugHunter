# Installation Guide - CVE Framework v4.1

## 📦 Prerequisites

- **Python**: 3.7 or higher
- **Operating System**: Windows, Linux, or macOS
- **Permissions**: Appropriate authorization for security testing

## 🚀 Quick Install

### Option 1: Full Installation (Recommended)

Install all dependencies for complete functionality:

```powershell
# Windows PowerShell
pip install aiohttp requests cryptography numpy scikit-learn joblib fake-useragent urllib3
```

```bash
# Linux/macOS
pip3 install aiohttp requests cryptography numpy scikit-learn joblib fake-useragent urllib3
```

### Option 2: Minimal Installation

For basic functionality without ML features:

```powershell
# Windows PowerShell
pip install aiohttp requests cryptography fake-useragent urllib3
```

## 📋 Dependency Details

### Required Dependencies
- **aiohttp** - Async HTTP client for high-performance scanning
- **requests** - HTTP library for exploit execution
- **cryptography** - Secure credential storage
- **urllib3** - HTTP library utilities
- **fake-useragent** - User-agent rotation for evasion

### Optional Dependencies (for ML features)
- **numpy** - Numerical computing
- **scikit-learn** - Machine learning models
- **joblib** - Model persistence

### Standard Library (included with Python)
- asyncio, concurrent.futures, threading, time, random
- hashlib, secrets, json, base64, urllib.parse
- sqlite3, datetime, pathlib, logging, sys, os, re

## ✅ Verify Installation

```powershell
# Check Python version
python --version

# Test import (should show no errors)
python -c "import aiohttp, requests, cryptography; print('✅ Core dependencies OK')"

# Test ML dependencies (optional)
python -c "import numpy, sklearn, joblib; print('✅ ML dependencies OK')"

# Test the framework
python cve.py --health-check
```

## 🔧 Configuration

### 1. Create Configuration File (Optional)

The framework works with defaults, but you can customize:

```powershell
# Copy example config
copy framework_config_example.json framework_config.json

# Edit as needed
notepad framework_config.json
```

### 2. Set Master Password (for credential storage)

```powershell
# Set environment variable
$env:CVE_MASTER_PASSWORD = "YourSecurePassword123!"

# Or set permanently (Windows)
[Environment]::SetEnvironmentVariable("CVE_MASTER_PASSWORD", "YourSecurePassword123!", "User")
```

## 🎯 First Run

### Basic Health Check

```powershell
python cve.py --health-check
```

Expected output:
```json
{
  "status": "healthy",
  "uptime_seconds": 0.5,
  "performance_score": 100.0,
  ...
}
```

### Test Scan (Safe)

```powershell
# Scan localhost (safe test)
python cve.py --targets 127.0.0.1:8080
```

## 🐛 Troubleshooting

### Issue: "Import aiohttp could not be resolved"

**Solution:**
```powershell
pip install aiohttp
```

### Issue: "ML libraries not available"

This is a warning, not an error. The framework will work without ML features.

**To enable ML:**
```powershell
pip install numpy scikit-learn joblib
```

### Issue: "SSL certificate verification failed"

**Solution:** Disable SSL verification in config:
```json
{
  "targets": {
    "verify_ssl": false
  }
}
```

### Issue: "Permission denied"

**Windows:** Run PowerShell as Administrator
**Linux/macOS:** Use `sudo` if needed

### Issue: Python not found

**Windows:**
1. Install Python from python.org
2. Check "Add Python to PATH" during installation
3. Restart PowerShell

**Linux:**
```bash
sudo apt-get install python3 python3-pip
```

**macOS:**
```bash
brew install python3
```

## 📂 Directory Structure

After installation, create this structure:

```
cve-framework/
├── cve.py                          # Main framework file
├── framework_config.json           # Your configuration (optional)
├── framework_config_example.json   # Configuration template
├── README_v4.1.md                  # Documentation
├── QUICKSTART.md                   # Quick start guide
├── CHANGELOG.md                    # Version history
├── logs/                           # Log files (auto-created)
│   ├── audit.json
│   └── performance.json
├── models/                         # ML models (auto-created)
│   ├── fp_classifier.pkl
│   └── vuln_predictor.pkl
└── reports/                        # Generated reports (auto-created)
    └── security_assessment.json
```

## 🔒 Security Setup

### 1. Secure Credentials

```powershell
# Set master password
$env:CVE_MASTER_PASSWORD = "SecurePassword123!"

# Store credentials (if using authentication)
python cve.py --store-credential --id production_admin
```

### 2. File Permissions

```powershell
# Windows: Restrict access to config file
icacls framework_config.json /grant:r "YourUsername:F"
icacls .credentials.enc /grant:r "YourUsername:F"
```

```bash
# Linux/macOS: Set secure permissions
chmod 600 framework_config.json
chmod 600 .credentials.enc
```

### 3. Audit Logging

Enable in config:
```json
{
  "logging": {
    "enable_audit_logging": true,
    "audit_log_file": "logs/audit.json"
  }
}
```

## 🌐 Enterprise Integration Setup

### SIEM Integration (Splunk Example)

1. **Get Splunk HEC Token**
   - Go to Splunk > Settings > Data Inputs > HTTP Event Collector
   - Create new token

2. **Configure Framework**
```json
{
  "integrations": {
    "siem": {
      "enabled": true,
      "type": "splunk",
      "hec_url": "https://your-splunk:8088/services/collector",
      "hec_token": "YOUR-TOKEN-HERE"
    }
  }
}
```

3. **Test Connection**
```powershell
python cve.py --targets test.example.com --push-siem
```

### Jira Integration

1. **Get API Token**
   - Jira > Account Settings > Security > API Tokens

2. **Configure Framework**
```json
{
  "integrations": {
    "ticketing": {
      "enabled": true,
      "type": "jira",
      "url": "https://your-domain.atlassian.net",
      "username": "your-email@example.com",
      "api_token": "YOUR-API-TOKEN",
      "project_key": "SEC"
    }
  }
}
```

3. **Test Integration**
```powershell
python cve.py --targets test.example.com --create-tickets
```

## 📊 Performance Tuning

### For High-Volume Scanning

```json
{
  "execution": {
    "max_workers": 50,
    "max_concurrent": 100,
    "requests_per_second": 50
  },
  "performance": {
    "pool_size": 200,
    "memory_limit_mb": 4096
  }
}
```

### For Resource-Constrained Systems

```json
{
  "execution": {
    "max_workers": 5,
    "max_concurrent": 10,
    "requests_per_second": 5
  },
  "performance": {
    "memory_limit_mb": 512
  }
}
```

## 🎓 Next Steps

1. ✅ **Read QUICKSTART.md** - Learn common use cases
2. ✅ **Review README_v4.1.md** - Understand all features
3. ✅ **Run test scan** - Verify everything works
4. ✅ **Configure integrations** - Connect to your tools
5. ✅ **Start scanning** - Begin security testing

## 📞 Getting Help

### Check System Status
```powershell
python cve.py --health-check
python cve.py --show-metrics
```

### View Logs
```powershell
# Application log
type cve_framework.log

# Audit log
type logs\audit.json

# Performance log  
type logs\performance.json
```

### Test Individual Components
```powershell
# Test fingerprinting
python cve.py --targets example.com --fingerprint

# Test WAF detection
python cve.py --targets example.com --detect-waf

# Test compliance
python cve.py --targets example.com --compliance-check
```

## ⚠️ Important Notes

### Legal Compliance
- ✅ Obtain written authorization before scanning
- ✅ Comply with applicable laws and regulations
- ✅ Follow responsible disclosure practices
- ✅ Respect engagement scope and limitations

### Best Practices
- ✅ Start with test targets
- ✅ Monitor system resources
- ✅ Review reports regularly
- ✅ Keep logs for compliance
- ✅ Update dependencies regularly

### Backup & Recovery
```powershell
# Backup configuration
copy framework_config.json framework_config.backup.json

# Backup credentials
copy .credentials.enc .credentials.backup.enc

# Backup reports
xcopy /E /I reports reports_backup
```

## 🚀 You're Ready!

Installation complete! Start with:

```powershell
python cve.py --targets your-target.com --fingerprint --detect-waf
```

For more examples, see **QUICKSTART.md**

---

**Questions?** Review the documentation in README_v4.1.md
