# E-Gov Guardian 🛡️

**AI-Powered Security Scanner for Estonian Government Web Services**

E-Gov Guardian is a comprehensive security assessment platform designed specifically for Estonian digital infrastructure and government services. Built with deep expertise in Estonian e-ID authentication systems and powered by artificial intelligence, it helps Estonian developers secure their digital products and protect citizens' sensitive data through automated vulnerability detection with actionable remediation guidance.

🌐 **Live Demo:** <https://e-gov-guardian.onrender.com/>

## Why Estonian Developers Need E-Gov Guardian

Estonian digital services are among the most advanced in the world, handling sensitive citizen data and supporting critical infrastructure that millions of Estonians depend on daily. As an Estonian developer, you have the responsibility to maintain the highest security standards to protect citizens' personal information and ensure the integrity of Estonia's digital society.

Traditional security scanners often miss the nuanced security requirements of Estonian government systems, particularly the complex e-ID authentication flows and strict privacy compliance requirements. E-Gov Guardian was built specifically for Estonian developers to bridge this gap by combining:

- **Specialized Government Focus**: Deep understanding of government-specific security requirements
- **Estonian e-ID Expertise**: Comprehensive knowledge of Smart-ID, Mobile-ID, and e-ID authentication systems
- **AI-Powered Analysis**: Contextual security recommendations powered by OpenAI GPT-4o-mini
- **Production-Ready Deployment**: Professional reporting and enterprise-grade infrastructure

## Core Features

### 🔍 Comprehensive Vulnerability Detection

- **Web Application Security**: SQL injection, XSS, CSRF, and OWASP Top 10 vulnerabilities
- **API Security**: GraphQL introspection, endpoint fuzzing, and REST API security
- **Infrastructure Security**: TLS/SSL configuration, security headers, and network security
- **Authentication Security**: Specialized testing for Estonian e-ID systems
- **Compliance Assessment**: GDPR, eIDAS, and Estonian Trust Services compliance

### 🧠 AI-Powered Security Analysis

- **Contextual Recommendations**: GPT-4o-mini provides specific, actionable fix suggestions
- **Estonian Authentication Expertise**: OPENAI for Estonian digital identity security requirements
- **Concise Guidance**: Clear, technical recommendations without information overload
- **Risk Prioritization**: Intelligent severity assessment based on government security standards

### 📊 Professional Reporting

- **Executive Summaries**: High-level security assessments for stakeholders
- **Technical Reports**: Detailed vulnerability analysis for development teams
- **PDF Generation**: Professional, branded reports suitable for audit evidence
- **Multi-Language Support**: Available in English and Estonian
- **Compliance Mapping**: Direct correlation to regulatory requirements

### 🚀 Enterprise-Ready Infrastructure

- **Docker Containerization**: Consistent deployment across environments
- **Scalable Architecture**: Gunicorn + gevent for high-concurrency scanning
- **Memory-Efficient**: Intelligent caching with automatic cleanup
- **One-Click Deployment**: Render.com and Docker Compose support
- **Zero-Setup**: No complex ZAP GUI or VPN requirements

## Technical Architecture

E-Gov Guardian employs a dual-scanner architecture for comprehensive coverage:

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Interface                            │
│                 (Flask + Bootstrap 5)                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Security Scanner Engine                      │
├─────────────────────┬───────────────────────────────────────┤
│  Built-in Scanner   │           OWASP ZAP                   │
│  (Always Available) │         (Optional)                    │
└─────────────────────┼───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Estonian e-ID Specialist                       │
│        (Smart-ID, Mobile-ID, e-ID Testing)                  │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 AI Fix Advisor                              │
│              (OpenAI GPT-4o-mini)                           │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Report Generation                              │
│              (WeasyPrint PDF)                               │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Method 1: Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/uzaif-lab/E-Gov_Guardian.git
cd E-Gov_Guardian

# Build and run with Docker
docker build -t egov-guardian .
docker run -e OPENAI_API_KEY="your-api-key" -p 5000:5000 egov-guardian

# Access the application
open http://localhost:5000
```

### Method 2: Docker Compose

```bash
# Clone and configure
git clone https://github.com/uzaif-lab/E-Gov_Guardian.git
cd E-Gov_Guardian

<<<<<<< HEAD
# Edit docker-compose.yml to add your OpenAI API key
# Then run:
docker-compose up -d
```

### Method 3: Local Development

```bash
# Prerequisites: Python 3.11+, pip
git clone https://github.com/uzaif-lab/E-Gov_Guardian.git
cd E-Gov_Guardian

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export OPENAI_API_KEY="your-api-key"

# Run development server
python web_app.py
```

### Method 4: One-Click Cloud Deployment

Deploy to Render.com in under 2 minutes:

1. Fork this repository
2. Create a new **Web Service** on Render
3. Connect your forked repository
4. Set `OPENAI_API_KEY` environment variable
5. Deploy automatically

## Configuration

### Environment Variables

| Variable          | Description                      | Required   |
| ----------------- | -------------------------------- | ---------- |
| `OPENAI_API_KEY`  | OpenAI API key for AI analysis   | Optional\* |
| `WEB_CONCURRENCY` | Number of worker processes       | Optional   |
| `PORT`            | Application port (default: 5000) | Optional   |

\*AI analysis will be disabled if no API key is provided

### Advanced Configuration

Copy `config.template.yaml` to `config.yaml` for advanced settings:

```yaml
# AI Analysis Configuration
ai_analysis:
  enabled: true
  model: "gpt-4o-mini"
  max_tokens: 150
  temperature: 0.1

# Scanner Configuration
scanner:
  max_scan_time: 1800 # 30 minutes
  max_depth: 5
  deep_scan_depth: 8

# OWASP ZAP Integration (Optional)
zap:
  enabled: false
  host: "127.0.0.1"
  port: 8080
```

## Security Test Coverage

### Web Application Security

- ✅ SQL Injection (Error-based, Boolean-based, Time-based)
- ✅ Cross-Site Scripting (Reflected, Stored, DOM-based)
- ✅ Cross-Site Request Forgery (CSRF)
- ✅ Security Headers Analysis
- ✅ Cookie Security Assessment
- ✅ CORS Misconfiguration
- ✅ Open Redirect Vulnerabilities
- ✅ Host Header Injection
- ✅ Directory Traversal
- ✅ Command Injection

### API Security

- ✅ REST API Endpoint Fuzzing
- ✅ GraphQL Introspection and Security
- ✅ Subresource Integrity Verification
- ✅ HTTP Method Testing
- ✅ Information Disclosure

### Estonian e-ID Specific

- ✅ Smart-ID Authentication Flow Security
- ✅ Mobile-ID Implementation Testing
- ✅ e-ID Certificate Chain Validation
- ✅ TLS/SSL Configuration for e-ID Services
- ✅ Authentication Redirect Security
- ✅ Privacy and Data Protection Compliance

### Infrastructure Security

- ✅ TLS/SSL Configuration Testing
- ✅ Certificate Validation
- ✅ Network Security Assessment
- ✅ Service Discovery and Fingerprinting



### Authentication Methods Supported

- **Smart-ID**: Mobile app-based authentication
- **Mobile-ID**: SMS-based authentication
- **e-ID Card**: Physical card-based authentication

### Compliance Frameworks

- **eIDAS Regulation**: European digital identity standards
- **Estonian Trust Services**: National digital identity requirements
- **GDPR**: Privacy and data protection compliance

### Security Assessments

- Certificate chain validation for e-ID services
- Authentication flow security analysis
- Privacy risk assessment
- Cross-border interoperability security
=======
---
>>>>>>> db215cfebc695b5a6ebcb3f5f67cfa95ecfd6efb

## Technology Stack

### Backend

- **Python 3.11**: Core application runtime
- **Flask 3.1**: Web framework
- **Gunicorn + gevent**: Production WSGI server
- **OWASP ZAP**: Professional security scanning (optional)
- **OpenAI API**: AI-powered security analysis

### Frontend

- **Bootstrap 5**: Modern, responsive UI
- **Jinja2**: Template engine
- **Multi-language Support**: English and Estonian

### Security Tools

- **requests**: HTTP security testing
- **BeautifulSoup**: HTML parsing and analysis
- **Selenium**: Browser automation for complex authentication flows
- **python-nmap**: Network security scanning
- **cryptography**: TLS/SSL security assessment

### Reporting

- **WeasyPrint**: Professional PDF generation
- **ReportLab**: Advanced report layouts
- **JSON API**: Programmatic access to results

## API Reference

### Start Security Scan

```http
POST /scan
Content-Type: application/x-www-form-urlencoded

target_url=https://example.com
&deep_scan=true
&ai_analysis=true
&test_sql_injection=true
&test_xss=true
```

### Get Scan Results

```http
GET /api/scan-results/{scan_id}
```

### Download PDF Report

```http
GET /download/{scan_id}
```

### Estonian e-ID Scan

```http
POST /estonian-scan
Content-Type: application/x-www-form-urlencoded

estonian_url=https://login.eesti.ee
&estonian_ai_analysis=true
```

## Contributing to Estonia's Digital Security

I welcome contributions from Estonian developers, security researchers, and government technologists who are passionate about protecting Estonian citizens' data and improving our nation's digital infrastructure security. Together, we can ensure Estonia maintains its position as a global leader in secure digital governance.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/uzaif-lab/E-Gov_Guardian.git
cd E-Gov_Guardian

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest

# Start development server
python web_app.py
```

## Deployment

### Production Deployment Checklist

- [ ] Configure `OPENAI_API_KEY` environment variable
- [ ] Set appropriate `WEB_CONCURRENCY` for your infrastructure
- [ ] Configure reverse proxy (nginx/Apache) with SSL termination
- [ ] Set up monitoring and logging
- [ ] Configure backup and disaster recovery
- [ ] Implement rate limiting and DDoS protection
- [ ] Review and customize security scan configurations

### Monitoring

Monitor these key metrics in production:

- Response time for security scans
- Memory usage during concurrent scans
- AI API usage and costs
- Scan completion rates
- Error rates and types

## Support for Estonian Developers

### Getting Help

- **GitHub Issues**: Report bugs, request features, and discuss improvements with fellow Estonian developers
- **Security Issues**: Contact maintainers privately for security vulnerabilities - protecting citizens' data is our top priority
- **Estonian e-ID Questions**: Specialized support for Estonian authentication systems (Smart-ID, Mobile-ID, e-ID Card)
- **Community Support**: Connect with other Estonian developers working on digital government security

### Learning Resources for Estonian Developers

- **Estonian e-ID Security Documentation**: Official security guidelines and best practices
- **OWASP Security Testing Guide**: International security standards adapted for Estonian context
- **eIDAS Regulation Compliance Guide**: European digital identity requirements
- **Estonian Government Web Security Best Practices**: National security standards
- **RIA (Riigi Infosüsteemi Amet) Security Guidelines**: Official Estonian government IT security requirements

## License and Attribution

**MIT License** © 2024 Mohd Uzaif Khan

E-Gov Guardian is developed with the mission of improving digital government security in Estonia and protecting Estonian citizens' data. This project is dedicated to the public good and the advancement of secure digital governance in Estonia.

As Estonian developers, we have a unique opportunity and responsibility to maintain Estonia's position as a global leader in digital governance. Every line of code we write, every security measure we implement, and every vulnerability we prevent helps protect the personal data and digital rights of our fellow citizens.

---

_"Securing digital government services for Estonian citizens - because their trust in our digital society depends on it"_

**E-Gov Guardian** - Professional security assessment for Estonia's digital future.

---

<<<<<<< HEAD
### 🇪🇪 For Estonian Developers

This tool was created specifically for the Estonian developer community. Whether you're working on government portals, e-services, or any digital product that serves Estonian citizens, E-Gov Guardian helps you maintain the security standards that our digital society depends on.


=======
## License

MIT © Mohd Uzaif Khan – _secure software for the public good._
>>>>>>> db215cfebc695b5a6ebcb3f5f67cfa95ecfd6efb
