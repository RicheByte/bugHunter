# BugHunter Pro v5.0 Enterprise - Installation Guide

## 🚀 Quick Start

### Basic Installation
```bash
# Clone repository
git clone https://github.com/RicheByte/cveAutometer.git
cd cveAutometer

# Install core dependencies
pip install requests beautifulsoup4 lxml
```

### Full Enterprise Installation
```bash
# Install all enterprise features
pip install -r requirements-enterprise.txt
```

---

## 📦 Installation Options

### Option 1: Minimal Installation (Core Features Only)
```bash
pip install requests beautifulsoup4
```

**Features Included:**
- ✅ 50+ vulnerability detection modules
- ✅ Smart web crawling
- ✅ WAF detection
- ✅ JSON reporting
- ✅ HMAC audit logging
- ✅ Circuit breaker pattern

**Features NOT Included:**
- ❌ ML false positive reduction
- ❌ Advanced retry strategies
- ❌ Distributed caching (Redis)
- ❌ PDF report generation
- ❌ Multi-format reporting

---

### Option 2: Standard Installation (Most Common)
```bash
pip install requests beautifulsoup4 lxml numpy scikit-learn joblib
```

**Additional Features:**
- ✅ ML-powered false positive reduction
- ✅ Vulnerability prediction
- ✅ Adaptive learning
- ✅ Better accuracy

---

### Option 3: Enterprise Installation (Full Features)
```bash
pip install -r requirements-enterprise.txt
```

**All Features:**
- ✅ Everything from Standard
- ✅ Advanced retry strategies (tenacity)
- ✅ Distributed caching (Redis)
- ✅ Professional PDF reports (reportlab)
- ✅ Async scanning capabilities
- ✅ Performance monitoring
- ✅ Advanced cryptography

---

## 🐳 Docker Installation

### Build Docker Image
```bash
# Create Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements-enterprise.txt .
RUN pip install --no-cache-dir -r requirements-enterprise.txt

# Copy scanner
COPY bughunter.py .

# Create directories
RUN mkdir -p /app/reports /app/logs

ENTRYPOINT ["python", "bughunter.py"]
CMD ["--help"]
EOF

# Build image
docker build -t bughunter-pro:v5.0 .
```

### Run with Docker
```bash
# Basic scan
docker run --rm bughunter-pro:v5.0 -u https://example.com

# Advanced scan with volume mounting
docker run --rm \
  -v $(pwd)/reports:/app/reports \
  bughunter-pro:v5.0 \
  -u https://example.com \
  --enable-ml \
  --enable-compliance
```

### Docker Compose with Redis
```yaml
# docker-compose.yml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
  
  bughunter:
    build: .
    depends_on:
      - redis
    environment:
      - REDIS_URL=redis://redis:6379
    volumes:
      - ./reports:/app/reports
    command: >
      -u https://example.com
      --enable-ml
      --enable-compliance
      --redis-url redis://redis:6379

volumes:
  redis-data:
```

Run with:
```bash
docker-compose up
```

---

## ☸️ Kubernetes Deployment

### ConfigMap
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: bughunter-config
data:
  config.json: |
    {
      "max_threads": 100,
      "timeout": 15,
      "enable_ml": true,
      "enable_compliance": true,
      "enable_evasion": true
    }
```

### Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: bughunter-pro
spec:
  replicas: 1
  selector:
    matchLabels:
      app: bughunter
  template:
    metadata:
      labels:
        app: bughunter
    spec:
      containers:
      - name: bughunter
        image: bughunter-pro:v5.0
        env:
        - name: REDIS_URL
          value: "redis://redis-service:6379"
        volumeMounts:
        - name: reports
          mountPath: /app/reports
      volumes:
      - name: reports
        persistentVolumeClaim:
          claimName: bughunter-reports
```

### CronJob for Scheduled Scans
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
            image: bughunter-pro:v5.0
            args:
              - "-u"
              - "https://example.com"
              - "--enable-ml"
              - "--enable-compliance"
              - "--redis-url"
              - "redis://redis-service:6379"
          restartPolicy: OnFailure
```

---

## 🔧 Redis Setup (Optional)

### Local Redis
```bash
# Install Redis (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Test connection
redis-cli ping
# Should return: PONG
```

### Redis with Docker
```bash
# Run Redis container
docker run -d \
  --name redis \
  -p 6379:6379 \
  redis:7-alpine

# Verify
docker exec -it redis redis-cli ping
```

### Redis Cloud (Free Tier)
1. Sign up at https://redis.com/try-free/
2. Create database
3. Get connection URL
4. Use with `--redis-url` flag

---

## 🧪 Verify Installation

### Test Core Features
```bash
python bughunter.py --help
```

### Test ML Features
```python
python -c "import numpy, sklearn, joblib; print('ML: OK')"
```

### Test Redis Connection
```python
python -c "import redis; r=redis.Redis(); r.ping(); print('Redis: OK')"
```

### Test PDF Generation
```python
python -c "from reportlab.lib.pagesizes import letter; print('PDF: OK')"
```

### Full System Test
```bash
python bughunter.py -u http://testphp.vulnweb.com \
  --enable-ml \
  --enable-compliance \
  --report-formats json html csv sarif markdown
```

---

## 🐛 Troubleshooting

### Issue: "Module not found"
```bash
# Ensure all dependencies installed
pip install -r requirements-enterprise.txt

# Or install individually
pip install requests beautifulsoup4 numpy scikit-learn
```

### Issue: "Redis connection failed"
```bash
# Check Redis is running
redis-cli ping

# Start Redis if needed
sudo systemctl start redis-server

# Or use without Redis (local cache only)
python bughunter.py -u https://example.com
```

### Issue: "PDF generation failed"
```bash
# Install reportlab
pip install reportlab

# Or skip PDF reports
python bughunter.py -u https://example.com --report-formats json html csv
```

### Issue: "Permission denied"
```bash
# Run with proper permissions
sudo python bughunter.py -u https://example.com

# Or fix permissions
chmod +x bughunter.py
```

### Issue: "SSL Certificate verification failed"
```bash
# Already handled by default (verify_ssl=False)
# But if needed:
export PYTHONHTTPSVERIFY=0
```

---

## 📊 Performance Tuning

### High-Performance Setup
```bash
# Install with performance optimizations
pip install -r requirements-enterprise.txt

# Use Redis for caching
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run with optimized settings
python bughunter.py -u https://example.com \
  --threads 200 \
  --delay 0.01 \
  --max-pages 5000 \
  --redis-url redis://localhost:6379
```

### Memory-Constrained Setup
```bash
# Reduce threads and cache
python bughunter.py -u https://example.com \
  --threads 10 \
  --max-pages 100
```

---

## 🔐 Security Hardening

### Production Deployment
```bash
# Create dedicated user
sudo useradd -m -s /bin/bash bughunter

# Install in virtual environment
sudo -u bughunter python3 -m venv /home/bughunter/venv
sudo -u bughunter /home/bughunter/venv/bin/pip install -r requirements-enterprise.txt

# Run as dedicated user
sudo -u bughunter /home/bughunter/venv/bin/python bughunter.py -u https://example.com
```

### Audit Log Protection
```bash
# Protect audit key
chmod 600 .audit_key

# Protect audit database
chmod 600 audit.db
```

---

## 🎓 Next Steps

After installation:

1. **Basic Scan**: `python bughunter.py -u https://example.com`
2. **Read Documentation**: `ENTERPRISE_IMPROVEMENTS.md`
3. **Developer Guide**: `DEVELOPER_GUIDE.md`
4. **Create Custom Plugins**: See developer guide
5. **Setup CI/CD Integration**: See GitHub Actions examples

---

## 📞 Support

- **Issues**: https://github.com/RicheByte/cveAutometer/issues
- **Documentation**: Check `docs/` folder
- **Community**: GitHub Discussions

---

**Installation complete! Ready to hunt bugs! 🎯**
