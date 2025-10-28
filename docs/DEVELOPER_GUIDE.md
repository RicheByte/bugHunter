# BugHunter Pro v5.0 - Developer Quick Reference

## 🎯 Enterprise Components Quick Reference

### Service Registry
```python
# Register a service
service_registry = ServiceRegistry()
service_registry.register('my_service', my_service_instance)

# Get a service
service = service_registry.get('my_service')

# Check if service exists
if service_registry.has('my_service'):
    service = service_registry.get('my_service')
```

### Plugin System
```python
# Create a custom plugin
class MyCustomScanner(ScannerPlugin):
    @property
    def name(self) -> str:
        return "My Custom Scanner"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: ScanConfig):
        self.config = config
    
    def scan(self, target: Any) -> List[Vulnerability]:
        # Your scanning logic here
        return vulnerabilities
    
    def cleanup(self):
        # Cleanup resources
        pass

# Load and use plugin
plugin_manager = PluginManager()
plugin_manager.load_plugin(MyCustomScanner())
plugin_manager.enable_plugin("My Custom Scanner")
```

### Distributed Cache
```python
# Create cache instance
cache = DistributedCache(redis_url="redis://localhost:6379")

# Set value
cache.set("key", "value", ttl=3600)

# Get value
value = cache.get("key")

# Get statistics
stats = cache.get_stats()
print(f"Cache hit rate: {stats['hit_rate']}")
```

### Using @cached Decorator
```python
@cached(ttl=1800)  # Cache for 30 minutes
def expensive_fingerprint(url: str) -> Dict:
    # Expensive operation here
    return result
```

### Connection Pool
```python
# Create pool
pool = ConnectionPool(pool_size=100, pool_maxsize=200)

# Get session for domain
session = pool.get_session("example.com")
response = session.get("https://example.com")

# Close all connections
pool.close_all()
```

### Retry Strategy
```python
# Use retry decorator
@RetryStrategy.with_exponential_backoff(max_attempts=3, min_wait=1, max_wait=10)
def unreliable_request(url):
    return requests.get(url)
```

### Error Tracker
```python
# Create tracker
error_tracker = ErrorTracker()

# Log error
try:
    risky_operation()
except Exception as e:
    error_tracker.log_error(
        error_type="network_error",
        url="https://example.com",
        details="Connection timeout",
        exception=e
    )

# Get summary
summary = error_tracker.get_summary()

# Export to file
error_tracker.export_errors("errors.json")
```

### Report Generator
```python
# Generate reports
report_gen = EnterpriseReportGenerator(vulnerabilities, metrics)

# Generate specific formats
report_files = report_gen.generate([
    ReportFormat.JSON,
    ReportFormat.HTML,
    ReportFormat.SARIF
])

# Access generated files
print(f"HTML Report: {report_files['html']}")
print(f"SARIF Report: {report_files['sarif']}")
```

### CI/CD Integration
```python
# GitHub Actions annotations
annotations = CICDIntegration.export_for_github_actions(vulnerabilities)
print(annotations)

# Check security policy
policy = {'critical': 0, 'high': 2, 'medium': 10}
passed = CICDIntegration.check_security_policy(vulnerabilities, policy)

# Export Prometheus metrics
metrics_file = CICDIntegration.export_metrics_for_prometheus(metrics)
```

## 🔧 Configuration

### ScanConfig with All Options
```python
config = ScanConfig(
    max_threads=100,
    timeout=15,
    max_depth=5,
    follow_redirects=True,
    user_agent="BugHunter Pro v5.0",
    verify_ssl=False,
    max_crawl_pages=1000,
    rate_limit_delay=0.05,
    enable_evasion=True,
    enable_ml_filtering=True,
    enable_compliance=True,
    adaptive_rate_limit=True
)
```

## 🎨 Custom Scanner Example

```python
from bughunter import *

class CustomAPIScanner(ScannerPlugin):
    """Custom API vulnerability scanner"""
    
    @property
    def name(self) -> str:
        return "API Security Scanner"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def initialize(self, config: ScanConfig):
        self.config = config
        self.session = requests.Session()
    
    def scan(self, target: Any) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Your custom scanning logic
        try:
            # Example: Check for exposed API keys
            response = self.session.get(target.url)
            
            if 'api_key=' in response.text.lower():
                vuln = Vulnerability(
                    vuln_type="Exposed API Key",
                    severity=SeverityLevel.CRITICAL,
                    url=target.url,
                    evidence="API key found in response",
                    cwe="CWE-798",
                    owasp="A02:2021",
                    cvss_score=9.0,
                    remediation="Remove API keys from public responses"
                )
                vulnerabilities.append(vuln)
        
        except Exception as e:
            logging.error(f"Custom scanner error: {e}")
        
        return vulnerabilities
    
    def cleanup(self):
        self.session.close()

# Use custom scanner
scanner = BugHunterPro("https://api.example.com")
scanner.plugin_manager.load_plugin(CustomAPIScanner())
scanner.plugin_manager.enable_plugin("API Security Scanner")
vulnerabilities = scanner.run()
```

## 📊 Metrics Collection

```python
# Access scan metrics
metrics = scanner.scan_metrics

print(f"Duration: {metrics['duration']}s")
print(f"Requests: {metrics['requests_sent']}")
print(f"Targets: {metrics['targets_scanned']}")
print(f"Vulns Found: {metrics['vulns_found']}")
print(f"False Positives Filtered: {metrics['false_positives_filtered']}")
```

## 🔐 Security Best Practices

### 1. Rate Limiting
```python
# Use adaptive rate limiting
config.adaptive_rate_limit = True
config.rate_limit_delay = 0.1  # Base delay
```

### 2. Error Handling
```python
try:
    scanner = BugHunterPro(target_url, config)
    vulnerabilities = scanner.run()
except Exception as e:
    # Access error tracker
    error_summary = scanner.error_tracker.get_summary()
    logging.error(f"Scan failed: {error_summary}")
```

### 3. Audit Logging
```python
# All events are automatically logged
# Access audit log
audit_log = scanner.audit_logger.log_file
print(f"Audit log: {audit_log}")
```

## 🎯 Performance Tuning

### High-Speed Scanning
```python
config = ScanConfig(
    max_threads=200,           # More threads
    timeout=5,                 # Shorter timeout
    rate_limit_delay=0.01,     # Minimal delay
    adaptive_rate_limit=True,  # Auto-adjust
    max_crawl_pages=2000      # More pages
)
```

### Stealth Scanning
```python
config = ScanConfig(
    max_threads=10,            # Fewer threads
    timeout=30,                # Longer timeout
    rate_limit_delay=2.0,      # Longer delay
    enable_evasion=True,       # WAF evasion
    adaptive_rate_limit=False  # Fixed rate
)
```

## 📦 Integration Examples

### GitHub Actions Workflow
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          pip install requests beautifulsoup4 numpy scikit-learn
      
      - name: Run BugHunter Pro
        run: |
          python bughunter.py -u ${{ secrets.TARGET_URL }} \
            --enable-ml \
            --enable-compliance \
            --report-formats sarif
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: bughunter_sarif_*.json
```

### Docker Integration
```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY bughunter.py .

ENTRYPOINT ["python", "bughunter.py"]
CMD ["--help"]
```

### Kubernetes CronJob
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: bughunter-scan
spec:
  schedule: "0 2 * * *"  # 2 AM daily
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: bughunter
            image: bughunter:v5.0
            args:
              - "-u"
              - "https://example.com"
              - "--enable-ml"
              - "--enable-compliance"
              - "--redis-url"
              - "redis://redis-service:6379"
          restartPolicy: OnFailure
```

## 🎓 Advanced Usage Tips

1. **Use Redis for large-scale deployments**
   ```bash
   python bughunter.py -u https://example.com --redis-url redis://cache:6379
   ```

2. **Generate all report formats**
   ```bash
   python bughunter.py -u https://example.com --report-formats json html csv pdf sarif markdown
   ```

3. **Verbose debugging**
   ```bash
   python bughunter.py -u https://example.com -v
   ```

4. **Custom user agent**
   ```bash
   python bughunter.py -u https://example.com --user-agent "MyBot/1.0"
   ```

5. **Maximum performance**
   ```bash
   python bughunter.py -u https://example.com --threads 500 --delay 0.01 --max-pages 10000
   ```

## 📚 API Reference

Full component list:
- `ServiceRegistry` - Dependency injection container
- `PluginManager` - Plugin lifecycle management
- `ScannerPlugin` - Base plugin class
- `DistributedCache` - Multi-tier caching
- `ConnectionPool` - HTTP connection pooling
- `RetryStrategy` - Exponential backoff retry
- `ErrorTracker` - Centralized error management
- `EnterpriseReportGenerator` - Multi-format reporting
- `CICDIntegration` - CI/CD pipeline integration
- `ReportFormat` - Report format enumeration

---

**Happy Hunting! 🎯**
