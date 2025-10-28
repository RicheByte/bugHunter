# BugHunter Pro v5.0 - API Integration Guide

## 🌐 REST API Integration

### Overview
BugHunter Pro can be integrated with external systems via various APIs and webhooks.

---

## 📡 Webhook Support

### Sending Scan Results to Webhooks

```python
# Add to bughunter.py after CICDIntegration class

class WebhookIntegration:
    """Send scan results to webhooks"""
    
    @staticmethod
    def send_webhook(webhook_url: str, vulnerabilities: List[Vulnerability], 
                     scan_metrics: Dict[str, Any]) -> bool:
        """Send scan results to webhook endpoint"""
        try:
            payload = {
                "scan_completed": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "vulnerabilities": {
                    "total": len(vulnerabilities),
                    "critical": sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL),
                    "high": sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH),
                    "medium": sum(1 for v in vulnerabilities if v.severity == SeverityLevel.MEDIUM),
                    "low": sum(1 for v in vulnerabilities if v.severity == SeverityLevel.LOW),
                },
                "metrics": scan_metrics,
                "details": [v.to_dict() for v in vulnerabilities]
            }
            
            response = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            response.raise_for_status()
            logging.info(f"✓ Webhook sent successfully to {webhook_url}")
            return True
            
        except Exception as e:
            logging.error(f"✗ Webhook failed: {e}")
            return False
    
    @staticmethod
    def send_slack_notification(webhook_url: str, vulnerabilities: List[Vulnerability]) -> bool:
        """Send formatted Slack notification"""
        critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)
        
        color = "danger" if critical_count > 0 else "warning" if high_count > 0 else "good"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": "🔥 BugHunter Pro Scan Complete",
                "fields": [
                    {
                        "title": "Total Vulnerabilities",
                        "value": str(len(vulnerabilities)),
                        "short": True
                    },
                    {
                        "title": "Critical",
                        "value": str(critical_count),
                        "short": True
                    },
                    {
                        "title": "High",
                        "value": str(high_count),
                        "short": True
                    }
                ],
                "footer": "BugHunter Pro v5.0",
                "ts": int(time.time())
            }]
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            logging.error(f"Slack notification failed: {e}")
            return False
    
    @staticmethod
    def send_teams_notification(webhook_url: str, vulnerabilities: List[Vulnerability]) -> bool:
        """Send formatted Microsoft Teams notification"""
        critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)
        
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "BugHunter Pro Scan Complete",
            "themeColor": "FF0000" if critical_count > 0 else "FFA500" if high_count > 0 else "00FF00",
            "title": "🔥 BugHunter Pro Scan Complete",
            "sections": [{
                "facts": [
                    {"name": "Total Vulnerabilities", "value": str(len(vulnerabilities))},
                    {"name": "Critical", "value": str(critical_count)},
                    {"name": "High", "value": str(high_count)},
                ]
            }]
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            return True
        except Exception as e:
            logging.error(f"Teams notification failed: {e}")
            return False
```

---

## 🎫 Jira Integration

### Create Jira Issues for Vulnerabilities

```python
class JiraIntegration:
    """Create Jira tickets for vulnerabilities"""
    
    def __init__(self, jira_url: str, username: str, api_token: str, project_key: str):
        self.jira_url = jira_url.rstrip('/')
        self.username = username
        self.api_token = api_token
        self.project_key = project_key
        self.auth = (username, api_token)
    
    def create_issue(self, vulnerability: Vulnerability) -> Optional[str]:
        """Create Jira issue for vulnerability"""
        
        priority_map = {
            SeverityLevel.CRITICAL: "Highest",
            SeverityLevel.HIGH: "High",
            SeverityLevel.MEDIUM: "Medium",
            SeverityLevel.LOW: "Low",
            SeverityLevel.INFO: "Lowest"
        }
        
        issue_data = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"{vulnerability.vuln_type} - {vulnerability.url[:50]}",
                "description": f"""
*Vulnerability Type:* {vulnerability.vuln_type}
*Severity:* {vulnerability.severity.value.upper()}
*CVSS Score:* {vulnerability.cvss_score}
*CWE:* {vulnerability.cwe}
*OWASP:* {vulnerability.owasp}

*URL:* {vulnerability.url}
*Parameter:* {vulnerability.parameter}

*Evidence:*
{vulnerability.evidence}

*Remediation:*
{vulnerability.remediation}

*Detected by:* BugHunter Pro v5.0
*Timestamp:* {vulnerability.timestamp}
                """,
                "issuetype": {"name": "Bug"},
                "priority": {"name": priority_map.get(vulnerability.severity, "Medium")},
                "labels": ["security", "bughunter", vulnerability.severity.value]
            }
        }
        
        try:
            response = requests.post(
                f"{self.jira_url}/rest/api/2/issue",
                json=issue_data,
                auth=self.auth,
                headers={"Content-Type": "application/json"},
                timeout=15
            )
            
            response.raise_for_status()
            issue_key = response.json().get("key")
            logging.info(f"✓ Created Jira issue: {issue_key}")
            return issue_key
            
        except Exception as e:
            logging.error(f"✗ Failed to create Jira issue: {e}")
            return None
    
    def create_issues_batch(self, vulnerabilities: List[Vulnerability], 
                           severity_threshold: SeverityLevel = SeverityLevel.MEDIUM) -> List[str]:
        """Create Jira issues for vulnerabilities above threshold"""
        created_issues = []
        
        severity_order = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1
        }
        
        threshold_level = severity_order[severity_threshold]
        
        for vuln in vulnerabilities:
            if severity_order[vuln.severity] >= threshold_level:
                issue_key = self.create_issue(vuln)
                if issue_key:
                    created_issues.append(issue_key)
                time.sleep(1)  # Rate limiting
        
        return created_issues
```

---

## 📊 Splunk Integration

### Send Events to Splunk

```python
class SplunkIntegration:
    """Send scan results to Splunk"""
    
    def __init__(self, hec_url: str, hec_token: str):
        self.hec_url = hec_url.rstrip('/')
        self.hec_token = hec_token
    
    def send_event(self, vulnerability: Vulnerability) -> bool:
        """Send single vulnerability as event"""
        event = {
            "event": {
                "vulnerability_type": vulnerability.vuln_type,
                "severity": vulnerability.severity.value,
                "url": vulnerability.url,
                "parameter": vulnerability.parameter,
                "cvss_score": vulnerability.cvss_score,
                "cwe": vulnerability.cwe,
                "owasp": vulnerability.owasp,
                "evidence": vulnerability.evidence,
                "timestamp": vulnerability.timestamp
            },
            "sourcetype": "bughunter:vulnerability",
            "source": "BugHunter Pro v5.0"
        }
        
        try:
            response = requests.post(
                f"{self.hec_url}/services/collector/event",
                json=event,
                headers={
                    "Authorization": f"Splunk {self.hec_token}",
                    "Content-Type": "application/json"
                },
                timeout=10
            )
            
            response.raise_for_status()
            return True
            
        except Exception as e:
            logging.error(f"Splunk event failed: {e}")
            return False
    
    def send_events_batch(self, vulnerabilities: List[Vulnerability]) -> int:
        """Send multiple vulnerabilities"""
        success_count = 0
        
        for vuln in vulnerabilities:
            if self.send_event(vuln):
                success_count += 1
        
        logging.info(f"Sent {success_count}/{len(vulnerabilities)} events to Splunk")
        return success_count
```

---

## 📧 Email Notifications

### Send Email Reports

```python
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

class EmailIntegration:
    """Send email notifications with reports"""
    
    def __init__(self, smtp_server: str, smtp_port: int, username: str, 
                 password: str, from_email: str):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
    
    def send_report(self, to_emails: List[str], vulnerabilities: List[Vulnerability],
                    report_files: Dict[str, str]) -> bool:
        """Send scan report via email"""
        
        critical_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for v in vulnerabilities if v.severity == SeverityLevel.HIGH)
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = ', '.join(to_emails)
        msg['Subject'] = f"🔥 BugHunter Pro Scan: {len(vulnerabilities)} vulnerabilities found"
        
        body = f"""
BugHunter Pro v5.0 Scan Complete

Summary:
- Total Vulnerabilities: {len(vulnerabilities)}
- Critical: {critical_count}
- High: {high_count}

Please review the attached reports for detailed findings.

---
BugHunter Pro v5.0 Enterprise
Automated Security Scanner
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach report files
        for format_name, filepath in report_files.items():
            if filepath and Path(filepath).exists():
                try:
                    with open(filepath, 'rb') as f:
                        part = MIMEBase('application', 'octet-stream')
                        part.set_payload(f.read())
                    
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename={Path(filepath).name}'
                    )
                    msg.attach(part)
                except Exception as e:
                    logging.error(f"Failed to attach {filepath}: {e}")
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.username, self.password)
            server.send_message(msg)
            server.quit()
            
            logging.info(f"✓ Email sent to {', '.join(to_emails)}")
            return True
            
        except Exception as e:
            logging.error(f"✗ Email failed: {e}")
            return False
```

---

## 🔗 Integration Usage Examples

### Example 1: Webhook + Slack
```bash
python bughunter.py -u https://example.com \
  --enable-ml \
  --webhook-url https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
  --notification-type slack
```

### Example 2: Jira Issue Creation
```bash
python bughunter.py -u https://example.com \
  --enable-compliance \
  --jira-url https://your-domain.atlassian.net \
  --jira-project SEC \
  --jira-token YOUR_API_TOKEN \
  --jira-threshold high
```

### Example 3: Splunk Integration
```bash
python bughunter.py -u https://example.com \
  --splunk-hec-url https://splunk.example.com:8088 \
  --splunk-token YOUR_HEC_TOKEN
```

### Example 4: Email Reports
```bash
python bughunter.py -u https://example.com \
  --enable-ml \
  --email-to security@example.com,manager@example.com \
  --smtp-server smtp.gmail.com \
  --smtp-port 587
```

---

## 🎯 Full Integration Example

```python
# In your BugHunterPro._generate_report() method, add:

# Send notifications
if args.webhook_url:
    WebhookIntegration.send_webhook(
        args.webhook_url, 
        self.vulnerabilities, 
        self.scan_metrics
    )

if args.slack_webhook:
    WebhookIntegration.send_slack_notification(
        args.slack_webhook,
        self.vulnerabilities
    )

if args.jira_url and critical_or_high_vulns:
    jira = JiraIntegration(
        args.jira_url,
        args.jira_username,
        args.jira_token,
        args.jira_project
    )
    jira.create_issues_batch(self.vulnerabilities)

if args.splunk_hec_url:
    splunk = SplunkIntegration(
        args.splunk_hec_url,
        args.splunk_token
    )
    splunk.send_events_batch(self.vulnerabilities)

if args.email_to:
    email = EmailIntegration(
        args.smtp_server,
        args.smtp_port,
        args.smtp_username,
        args.smtp_password,
        args.email_from
    )
    email.send_report(
        args.email_to.split(','),
        self.vulnerabilities,
        report_files
    )
```

---

## 📊 Supported Integrations

| Integration | Status | Description |
|-------------|--------|-------------|
| **Webhooks** | ✅ Ready | Generic webhook support |
| **Slack** | ✅ Ready | Slack notifications |
| **Microsoft Teams** | ✅ Ready | Teams notifications |
| **Jira** | ✅ Ready | Automatic issue creation |
| **Splunk** | ✅ Ready | SIEM integration |
| **Email** | ✅ Ready | Email reports |
| **GitHub** | ✅ Ready | GitHub Actions annotations |
| **Prometheus** | ✅ Ready | Metrics export |
| **PagerDuty** | 🔜 Coming Soon | Incident management |
| **ServiceNow** | 🔜 Coming Soon | ITSM integration |

---

**Your scanner is now ready for enterprise-wide deployment! 🚀**
