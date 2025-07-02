# 🛡️ E-Gov Guardian Security Scanner

**Production-grade automated security assessment tool for web applications and source code analysis.**

## ✨ Core Features

### 🔍 **Comprehensive Security Assessment**

- **Web Application Scanning**: Deep vulnerability analysis of live web applications
- **Source Code Analysis**: Static analysis for security vulnerabilities
- **Infrastructure Assessment**: Port scanning and service enumeration
- **Configuration Analysis**: Security configuration review

### 🎯 **Advanced Vulnerability Detection**

- ✅ **SQL Injection** - Database injection attack detection
- ✅ **Cross-Site Scripting (XSS)** - Script injection vulnerability identification
- ✅ **Command Injection** - System command execution vulnerabilities
- ✅ **Security Headers** - Missing security header analysis
- ✅ **SSL/TLS Configuration** - Encryption and certificate analysis
- ✅ **Insecure Authentication** - Weak authentication mechanisms
- ✅ **Directory Traversal** - File system access vulnerabilities
- ✅ **Information Disclosure** - Sensitive data exposure
- ✅ **Dependency Vulnerabilities** - Outdated library detection
- ✅ **Hardcoded Secrets** - Embedded credential detection

### 📊 **Professional Reporting**

- **Risk Rating System** - CRITICAL/HIGH/MEDIUM/LOW classification
- **Compliance Scoring** - 0-100 security posture rating
- **Multiple Formats** - JSON, HTML, CSV output options
- **Executive Summary** - Management-ready security reports
- **Actionable Recommendations** - Specific remediation guidance

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Network access to target systems
- Administrative privileges (for port scanning)

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
```

### 🌐 Web Interface (Recommended)

**Launch the professional web interface:**

```bash
# Option 1: Direct launch (simple)
python web_app.py

# Option 2: Launcher with auto-setup (first time users)
python start_web_interface.py
```

**Then open your browser to: http://localhost:5000**

> **Note:** The launcher script automatically checks dependencies, opens your browser, and sets up the environment. Use `python web_app.py` for quick daily use.

#### ✨ Web Interface Features

- 🎯 **Easy URL Input** - Simply paste any URL and click scan
- ⚡ **Real-time Progress** - Watch scan progress with live updates
- 📊 **Professional Dashboard** - Beautiful vulnerability breakdown and analytics
- 📄 **PDF Reports** - Download comprehensive security assessment reports
- 🔒 **Government-grade UI** - Professional interface with security disclaimers
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile devices

#### 🖥️ Web Interface Workflow

1. **Enter Target URL** - Input the website you want to scan
2. **Configure Options** - Choose standard or deep scan
3. **Monitor Progress** - Watch real-time scanning phases
4. **Review Results** - Analyze vulnerabilities and risk ratings
5. **Download Report** - Get PDF report for documentation

### 💻 Command Line Usage (Alternative)

```bash
# Web application security assessment
python -m scanner.main_scanner --target https://your-website.com --type url

# Deep security assessment (extended coverage)
python -m scanner.main_scanner --target https://your-website.com --type url --deep

# Source code security analysis
python -m scanner.main_scanner --target /path/to/source/code --type source

# Generate HTML report
python -m scanner.main_scanner --target https://example.com --format html
```

## 📖 Advanced Usage

### 🌐 Web Interface Configuration

The web interface runs on **http://localhost:5000** by default and provides:

#### Scan Configuration

- **Target URL**: Any valid web URL (http/https)
- **Scan Types**: Standard scan (faster) or Deep scan (comprehensive)
- **Real-time Monitoring**: Live progress updates with visual phases
- **Automatic Report Generation**: Professional PDF reports

#### Report Features

- **Executive Summary**: Risk rating and compliance score
- **Vulnerability Breakdown**: Categorized by severity (Critical/High/Medium/Low)
- **Detailed Findings**: Technical details and remediation guidance
- **Professional PDF**: Download publication-ready security reports

#### Security Considerations

- **Local Access Only**: Interface runs locally for security
- **Temporary Storage**: Scan results stored temporarily and auto-deleted
- **Permission Validation**: Built-in disclaimers for ethical scanning

### 💻 Command Line Options

```bash
# Full option syntax
python -m scanner.main_scanner \
    --target <URL_or_PATH> \
    --type <url|source> \
    [--deep] \
    [--format <json|html|csv>] \
    [--output <report_file>] \
    [--config <config_file>] \
    [--no-zap] \
    [--verbose]
```

### Configuration

Edit `config.yaml` to customize scan parameters:

```yaml
# Scanner configuration
scanner:
  max_scan_time: 1800 # 30 minutes
  max_depth: 5
  thread_count: 10

# Vulnerability detection settings
vulnerabilities:
  sql_injection:
    enabled: true
    severity_threshold: "Medium"

  xss:
    enabled: true
    severity_threshold: "Medium"

  port_scan:
    enabled: true
    common_ports: [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443]

# Reporting options
reporting:
  output_format: "json"
  detailed_report: true
```

## 🔧 Scanner Modes

### 1. **Built-in API Scanner** (Default)

- No external dependencies required
- Pure API-based vulnerability detection
- Comprehensive security testing capabilities

### 2. **OWASP ZAP Integration** (Optional)

For enhanced capabilities, integrate with OWASP ZAP:

```bash
# Option A: Docker (Recommended)
docker run -u zap -p 8080:8080 -d owasp/zap2docker-stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true

# Option B: Local Installation
# Download ZAP from https://www.zaproxy.org/download/
zap.sh -daemon -port 8080

# Enable in config.yaml
zap:
  enabled: true
```

## 📊 Assessment Types

### Web Application Assessment

Comprehensive security testing including:

- **Reconnaissance**: URL discovery and mapping
- **Vulnerability Scanning**: Active security testing
- **Configuration Analysis**: Security header and SSL review
- **Infrastructure Assessment**: Port and service enumeration

### Source Code Assessment

Static analysis covering:

- **Security Pattern Detection**: Vulnerability pattern matching
- **Dependency Analysis**: Third-party library vulnerabilities
- **Configuration Review**: Insecure configuration detection
- **Secret Detection**: Hardcoded credential identification

## 🧪 Testing Your Scanner

### Quick Test with Web Interface

1. **Start the web interface:**

   ```bash
   python start_web_interface.py
   ```

2. **Open http://localhost:5000 in your browser**

3. **Test with safe targets:**

   ```
   # Safe test websites that allow security scanning
   https://httpbin.org          # HTTP testing service
   https://example.com          # Basic test site
   https://jsonplaceholder.typicode.com  # API testing
   ```

4. **Expected workflow:**
   - Enter URL → Start Scan → Monitor Progress → View Results → Download PDF

### Command Line Testing

```bash
# Quick functionality test
python -m scanner.main_scanner --target https://httpbin.org --type url --verbose

# Test report generation
python -m scanner.main_scanner --target https://httpbin.org --format html --output test_report.html
```

### Verify Installation

```bash
# Check all dependencies
python -c "import scanner.main_scanner; print('✅ Scanner ready!')"

# Test web interface dependencies
python -c "import flask, reportlab; print('✅ Web interface ready!')"
```

## 🎯 Use Cases

### **Enterprise Security Testing** 🏢

- **Web Interface**: Easy-to-use dashboard for security teams
- **Regular Assessments**: Scheduled security scans with PDF reporting
- **Management Reporting**: Executive summaries with compliance scores
- **DevSecOps Integration**: Command-line integration for CI/CD pipelines

### **Development Integration** 👨‍💻

- **Pre-deployment Scans**: Web interface for quick security checks
- **CI/CD Pipeline Checks**: Command-line automation for builds
- **Code Review Support**: Source code analysis capabilities
- **Security Regression Testing**: Automated vulnerability tracking

### **Security Auditing** 🔍

- **Client Assessments**: Professional PDF reports for stakeholders
- **Compliance Validation**: Standardized security scoring
- **Risk Assessment**: Visual dashboards with vulnerability breakdowns
- **Documentation**: Comprehensive technical and executive reporting

### **Government & Public Sector** 🏛️

- **Digital Infrastructure Security**: Comprehensive government website assessment
- **Compliance Reporting**: Standards-compliant security documentation
- **Inter-agency Coordination**: Shareable PDF reports for security teams
- **Public Trust**: Ensuring citizen-facing services are secure

## 📈 Report Analysis

### Risk Rating Interpretation

- **CRITICAL**: Immediate action required - system compromise likely
- **HIGH**: Urgent attention needed - significant security risk
- **MEDIUM**: Important issues - should be addressed soon
- **LOW**: Minor issues - address during maintenance windows

### Compliance Scoring

- **90-100**: Excellent security posture
- **75-89**: Good security with minor improvements needed
- **50-74**: Fair security requiring attention
- **0-49**: Poor security requiring immediate remediation

## 🔐 Security & Ethics

### Responsible Use

- ⚠️ **Only scan systems you own or have explicit permission to test**
- ⚠️ **Respect rate limits and avoid service disruption**
- ⚠️ **Handle scan reports securely - they contain sensitive information**
- ⚠️ **Follow responsible disclosure for third-party vulnerabilities**

### Legal Considerations

- Obtain written authorization before scanning external systems
- Comply with local laws and regulations
- Respect terms of service and usage policies
- Consider liability and insurance requirements

## 🛠️ Technical Architecture

```
E-Gov_Guardian/
├── scanner/                     # Core security scanner package
│   ├── main_scanner.py          # Primary orchestration engine
│   ├── builtin_scanner.py       # API-based vulnerability scanner
│   ├── zap_client.py           # OWASP ZAP integration
│   ├── vulnerability_detector.py # Additional security checks
│   └── report_generator.py      # Multi-format report generation
├── templates/                   # Web interface templates
│   ├── base.html               # Base template with styling
│   ├── index.html              # Main scan input form
│   ├── progress.html           # Real-time progress tracking
│   └── results.html            # Results dashboard with PDF download
├── web_app.py                  # Flask web application
├── start_web_interface.py      # Web interface launcher
├── config.yaml                 # Scanner configuration
└── requirements.txt            # Python dependencies (CLI + Web)
```

### Web Interface Components

- **Flask Backend**: Handles scan orchestration and PDF generation
- **Bootstrap Frontend**: Professional, responsive user interface
- **Real-time Updates**: WebSocket-like polling for live progress
- **PDF Generation**: ReportLab integration for professional reports
- **Security Features**: Input validation, CSRF protection, local-only access

## 🔄 Integration

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
- name: Security Assessment
  run: |
    python -m scanner.main_scanner \
      --target ${{ env.TARGET_URL }} \
      --type url \
      --format json \
      --output security-report.json

    # Fail build on critical findings
    if grep -q '"risk_rating": "CRITICAL"' security-report.json; then
      exit 1
    fi
```

### API Integration

```python
from scanner.main_scanner import SecurityScanner

# Programmatic usage
scanner = SecurityScanner("config.yaml")
results = scanner.scan_url("https://example.com")

if results['risk_rating'] in ['CRITICAL', 'HIGH']:
    # Handle high-risk findings
    alert_security_team(results)
```

## 📞 Support & Troubleshooting

### Common Issues

**Permission Denied (Port Scanning)**

```bash
# Linux/macOS - Run with elevated privileges
sudo python -m scanner.main_scanner --target example.com --type url

# Windows - Run as Administrator
```

**Module Not Found**

```bash
# Ensure all dependencies are installed
pip install -r requirements.txt
```

**Network Connectivity**

```bash
# Test target accessibility
curl -I https://target-website.com
```

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**🛡️ Secure your digital infrastructure with E-Gov Guardian Security Scanner**

_Professional-grade security assessment tool for enterprise environments_
