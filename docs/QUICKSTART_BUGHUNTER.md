# 🚀 BugHunter Pro - Quick Start Guide

## ⚡ 60-Second Setup

```powershell
# 1. Install dependencies
pip install beautifulsoup4 lxml aiohttp requests

# 2. Run a quick test
python demo_bughunter.py

# 3. Scan your first target
python bughunter.py -u http://testphp.vulnweb.com
```

## 🎯 Common Use Cases

### Bug Bounty Hunting
```powershell
# Fast, aggressive scan
python bughunter.py -u https://target.com --threads 100 --depth 5 --max-pages 2000
```

### Penetration Testing
```powershell
# Comprehensive scan
python bughunter.py -u https://client-app.com --threads 50 --depth 10
```

### Quick Security Check
```powershell
# Surface scan
python bughunter.py -u https://my-site.com --depth 2 --max-pages 100
```

## 📊 What It Finds

✅ **Critical Vulnerabilities**
- SQL Injection (CVSS 9.8)
- Command Injection (CVSS 9.8)
- SSRF (CVSS 8.6)

✅ **High Severity**
- XSS (CVSS 7.2)
- Path Traversal (CVSS 7.5)
- Blind Command Injection (CVSS 8.8)

✅ **Medium/Low**
- Open Redirects
- Security Misconfigurations
- Missing Security Headers

## 🔥 Demo Results

The included `demo_bughunter.py` shows the scanner **finding real SQL injections**:

```
✅ SUCCESS! Found SQL Injection

Type: SQL Injection
Severity: CRITICAL
Payload: ' OR '1'='1
Evidence: SQL error detected: 'sql syntax' in response
CVSS: 9.8

📊 Results: Found 2 SQL injection vulnerabilities
  - http://testphp.vulnweb.com/artists.php (parameter: artist)
  - http://testphp.vulnweb.com/listproducts.php (parameter: cat)
```

## 📁 Output

After each scan, you'll get:
- Console summary with color-coded severity
- Detailed JSON report (`bughunter_report_*.json`)
- Full evidence and remediation guidance

## 🛡️ Remember

⚠️ **Only scan targets you have permission to test!**

- ✅ Your own applications
- ✅ Authorized penetration tests
- ✅ Bug bounty programs (in scope)
- ❌ NEVER scan without permission

## 📚 Full Documentation

See `README_BUGHUNTER.md` for:
- Complete feature list (50+ vulnerability types)
- Advanced configuration
- Troubleshooting
- Performance tuning
- API reference

## 🎓 Practice Targets

Try these legal practice sites:
- http://testphp.vulnweb.com (demo shows it works!)
- https://demo.testfire.net
- http://demo.ine.local (requires setup)
- DVWA, WebGoat, Mutillidae (local setup)

## 💡 Pro Tips

1. **Start with demo**: Run `python demo_bughunter.py` first
2. **Use verbose mode**: Add `-v` to see what's happening
3. **Check the report**: JSON files have full details
4. **Adjust speed**: Use `--threads` and `--delay` for your needs
5. **Practice legally**: Test on authorized targets only

## 🐛 Troubleshooting

**No vulnerabilities found?**
- Check if you have permission
- Try the demo first: `python demo_bughunter.py`
- Increase `--depth` and `--max-pages`
- Check the JSON report for what was tested

**Too slow?**
- Increase `--threads` (try 100)
- Decrease `--delay` (try 0.05)
- Reduce `--timeout` (try 5)

**Errors?**
- Install dependencies: `pip install beautifulsoup4 lxml aiohttp requests`
- Check Python version (3.7+ required)
- Use verbose mode: `-v`

---

## ✨ Next Steps

1. ✅ Run the demo to verify it works
2. ✅ Read `README_BUGHUNTER.md` for full documentation
3. ✅ Get authorization for your target
4. ✅ Run your first scan
5. ✅ Review the JSON report
6. ✅ Report findings responsibly

**Happy hunting! 🔥**
