# CVE Framework v4.1 - Quick Start Guide

## 🚀 5-Minute Setup

### 1. Install Dependencies
```bash
pip install aiohttp requests cryptography numpy scikit-learn joblib fake-useragent urllib3
```

### 2. Basic Usage
```bash
# Simple scan
python cve.py --targets example.com

# With fingerprinting and WAF detection
python cve.py --targets example.com --fingerprint --detect-waf
```

### 3. View Results
Results are saved to `reports/security_assessment.json`

## 📋 Common Use Cases

### Scenario 1: Quick Vulnerability Assessment
```bash
python cve.py --targets 192.168.1.100:80 192.168.1.101:443 \
  --exploits sql_injection command_injection \
  --report-name quick_assessment
```

**What it does:**
- Tests for SQL injection and command injection
- Generates JSON report
- No compliance checking

**Time:** 2-5 minutes

---

### Scenario 2: Comprehensive Enterprise Scan
```bash
python cve.py --targets production-web-app.example.com \
  --fingerprint \
  --detect-waf \
  --compliance-check \
  --gap-analysis \
  --show-trends \
  --report-name monthly_compliance_scan
```

**What it does:**
- Fingerprints technology stack
- Detects WAF presence
- Tests for vulnerabilities
- Maps to compliance frameworks (NIST, PCI-DSS, ISO 27001)
- Generates gap analysis
- Shows vulnerability trends
- Creates comprehensive report

**Time:** 10-15 minutes

---

### Scenario 3: Continuous Monitoring Setup
```bash
# Schedule daily scans
python cve.py --targets @production_targets.txt \
  --schedule daily \
  --time 02:00 \
  --push-siem \
  --create-tickets
```

**What it does:**
- Schedules daily scans at 2 AM
- Automatically pushes findings to SIEM
- Creates tickets for new vulnerabilities
- Runs continuously

**Setup time:** 5 minutes
**Ongoing:** Automated

---

### Scenario 4: Compliance Audit Preparation
```bash
python cve.py --targets @all_assets.txt \
  --fingerprint \
  --compliance-check \
  --gap-analysis \
  --report-name annual_compliance_audit
```

**What it does:**
- Scans all assets
- Maps findings to compliance frameworks
- Generates detailed gap analysis
- Prioritizes remediation efforts

**Time:** 30-60 minutes (depending on asset count)

---

### Scenario 5: Risk Assessment & Forecasting
```bash
# First, run several scans to build history
python cve.py --targets @assets.txt --report-name scan_1
python cve.py --targets @assets.txt --report-name scan_2
python cve.py --targets @assets.txt --report-name scan_3

# Then generate analytics
python cve.py --analytics-only --show-trends --risk-forecast
```

**What it does:**
- Analyzes historical scan data
- Identifies vulnerability trends
- Forecasts future risk trajectory
- Calculates business KPIs

**Time:** 5 minutes for analytics

---

## 🎯 Feature Comparison

| Feature | Basic Scan | Enterprise Scan | Continuous Monitoring |
|---------|-----------|----------------|---------------------|
| Vulnerability Testing | ✅ | ✅ | ✅ |
| Fingerprinting | ❌ | ✅ | ✅ |
| WAF Detection | ❌ | ✅ | ✅ |
| ML Prediction | ❌ | ✅ | ✅ |
| Compliance Mapping | ❌ | ✅ | ✅ |
| Gap Analysis | ❌ | ✅ | ✅ |
| SIEM Integration | ❌ | ❌ | ✅ |
| Ticketing | ❌ | ❌ | ✅ |
| Scheduling | ❌ | ❌ | ✅ |
| Analytics | ❌ | ✅ | ✅ |

## 📊 Understanding Reports

### Report Sections

1. **Metadata**: Scan details, timestamp, framework version
2. **Executive Summary**: High-level findings, risk scores, business impact
3. **Compliance Status**: Framework-by-framework compliance mapping
4. **Gap Analysis**: Detailed compliance gaps and remediation priorities
5. **Analytics**: Trends, forecasts, KPIs
6. **Performance**: Scan performance metrics
7. **Detailed Findings**: Technical vulnerability details

### Key Metrics to Monitor

- **Overall Risk Score**: 0-10 scale
- **Compliance Score**: Percentage (0-100%)
- **Critical Findings**: Count of critical vulnerabilities
- **Success Rate**: Percentage of successful exploits
- **Performance Score**: System health (0-100)

## 🔧 Configuration Tips

### Minimal Configuration
No config file needed! Framework works with sensible defaults.

### Recommended Production Config
```json
{
  "execution": {
    "max_workers": 20,
    "requests_per_second": 10
  },
  "security": {
    "enable_evasion": true,
    "enable_ml_filtering": true
  },
  "reporting": {
    "compliance_frameworks": ["NIST-CSF", "PCI-DSS"]
  }
}
```

Save as `framework_config.json`

### Full Enterprise Config
Use `framework_config_example.json` as a template

## 🚨 Troubleshooting

### Issue: "ML libraries not available"
```bash
pip install numpy scikit-learn joblib
```

### Issue: SSL certificate errors
Add to config:
```json
{
  "targets": {
    "verify_ssl": false
  }
}
```

### Issue: Rate limiting / blocked by WAF
Adjust rate in config:
```json
{
  "execution": {
    "requests_per_second": 5
  },
  "security": {
    "enable_evasion": true
  }
}
```

### Issue: Memory usage too high
```json
{
  "performance": {
    "memory_limit_mb": 1024,
    "auto_optimize_memory": true
  }
}
```

## 📈 Progressive Usage Path

### Week 1: Learn the Basics
- Run basic scans
- Review JSON reports
- Understand findings

### Week 2: Add Intelligence
- Enable fingerprinting
- Detect WAFs
- Use ML predictions

### Week 3: Compliance
- Enable compliance checking
- Generate gap analysis
- Map to frameworks

### Week 4: Enterprise Features
- Set up SIEM integration
- Configure ticketing
- Schedule continuous scans

### Week 5: Advanced Analytics
- Build scan history
- Analyze trends
- Generate forecasts

## 🎓 Best Practices

1. **Start Small**: Begin with a few targets
2. **Build History**: Run multiple scans for better analytics
3. **Review Reports**: Don't just collect data, act on it
4. **Integrate**: Connect to your existing tools (SIEM, tickets)
5. **Automate**: Schedule regular scans
6. **Monitor**: Watch the health dashboard
7. **Improve**: Use adaptive learning to refine

## 📞 Getting Help

### Check Health Status
```bash
python cve.py --health-check
```

### View Metrics
```bash
python cve.py --show-metrics
```

### Review Logs
- Application log: `cve_framework.log`
- Audit log: `logs/audit.json`
- Performance log: `logs/performance.json`

## 🔐 Security Reminders

✅ **DO:**
- Get authorization before scanning
- Use in authorized penetration tests
- Review and act on findings
- Keep audit logs

❌ **DON'T:**
- Scan systems without permission
- Use against production without approval
- Ignore compliance requirements
- Share credentials in config files

## 🎯 Next Steps

1. ✅ Run your first basic scan
2. ✅ Enable fingerprinting and WAF detection
3. ✅ Add compliance checking
4. ✅ Set up integrations
5. ✅ Schedule continuous monitoring
6. ✅ Build analytics history
7. ✅ Generate executive reports

---

**Ready to start?**

```bash
python cve.py --targets your-target.com --fingerprint --detect-waf --compliance-check
```

**Questions?** Review `README_v4.1.md` for detailed documentation.
