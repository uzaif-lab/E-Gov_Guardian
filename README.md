# E-Gov Guardian 🛡️ – AI-Powered Security Scanner for Government Web Services

Protecting digital government infrastructure requires more than one-off pentests. E-Gov Guardian delivers continuous, AI-assisted security scanning for public-facing sites **and** Estonia’s e-ID login flows – all in a single, lightweight container.

🌐 **Live Demo:** <https://e-gov-guardian.onrender.com/>

---

## Why E-Gov Guardian?

1. **Government-grade focus** – Checks for Smart-ID / Mobile-ID specifics, PKI certificate chains, and strict privacy rules that generic scanners miss.
2. **AI Fix Advisor** – Short, actionable remediation tips (powered by OpenAI) surface next steps instead of dumping raw findings.
3. **Zero-setup** – Docker image and Render.com button get you scanning in minutes—no ZAP GUI, no VPN.
4. **Two-click PDF** – Non-technical stakeholders receive branded reports suitable for audit evidence.

---

## Key Features

| Category      | Highlights                                                                      |
| ------------- | ------------------------------------------------------------------------------- |
| Core Web Vuls | SQLi, XSS, CSRF, Security Headers, CORS, Host-Header, Open Redirects            |
| Advanced API  | GraphQL introspection, SRI integrity, endpoint fuzzing                          |
| Estonian e-ID | TLS/cert validation, malicious redirect checks, Smart-ID & Mobile-ID heuristics |
| AI Analysis   | GPT-4o-mini summaries (< 3 lines each) with direct remediation links            |
| Reporting     | Inline UI, JSON API, downloadable PDF with charts & compliance scores           |

---

## Quick Start

```bash
# 1. Clone & run with Docker
git clone https://github.com/yourname/E-Gov_Guardian.git
cd E-Gov_Guardian
docker build -t egov-guardian .
docker run -e OPENAI_API_KEY="sk-..." -p 5000:5000 egov-guardian

# 2. Browse to
open http://localhost:5000
```

### One-Click Deploy (Render)

1. Create a new **Docker** web service, point it at this repo.
2. Add env var `OPENAI_API_KEY` with your key.
3. (Optional) set `WEB_CONCURRENCY=1` for single-worker persistence.  
   Render will build & publish automatically.

---

## Architecture at a Glance

```mermaid
graph TD
  UI[Bootstrap 5 Front-end] --> Flask
  Flask -->|scan| SecurityScanner
  SecurityScanner --> Builtin[Vulnerability Detector]
  SecurityScanner --> ZAPClient[OWASP ZAP (opt)]
  SecurityScanner --> Estonian[Estonian Login Scanner]
  SecurityScanner --> AIAdvisor[GPT Fix Advisor]
  SecurityScanner --> ReportGen[WeasyPrint PDF]
```

_Concurrency:_ Gunicorn + gevent handles many scans with minimal RAM.  
_Persistence:_ Results cached in-memory (single worker) with optional Redis drop-in.

---

## Technology Stack

- Python 3.11, Flask 3.1
- Gunicorn 23 + gevent
- WeasyPrint 65 for PDF
- OWASP ZAP 2.x via python-owasp-zap-v2.4
- OpenAI Python SDK 1.x

---

## Roadmap

- ✅ Render & Docker parity
- ⏳ SSO integration for internal deployments
- ⏳ Redis/SQLite result store for multi-worker setups
- ⏳ Scheduled cron scans & email digests

---

## Contributing

Issues and PRs are welcome! Please read `CONTRIBUTING.md` for coding standards and branch flow.

---

## License

MIT © Mohd Uzaif Khan – _secure software for the public good._
