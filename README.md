# Advanced Web Security & Exposure Scanner

## 📌 Project Overview
The **Advanced Web Security Scanner** is a comprehensive Python-based security auditing framework. Designed for penetration testers and DevSecOps pipelines, it automates the discovery of misconfigured **HTTP Security Headers**, overly permissive **CORS policies**, insecure session cookies, SSL/TLS vulnerabilities, and exposed sensitive server files.

Built with a multithreaded architecture, the tool efficiently scales to scan dozens of targets simultaneously and generates structured JSON or CSV reports for seamless integration into SIEMs and vulnerability management dashboards.

---

## Enterprise Features
1. **Multithreaded Execution:** Utilizes `concurrent.futures` to perform high-speed parallel scanning of bulk URL lists.
2. **Comprehensive Header Audit:** Validates the presence of OWASP Top 10 mitigation headers (HSTS, CSP, X-Frame-Options, etc.) and detects information disclosure headers (`Server`, `X-Powered-By`).
3. **CORS Vulnerability Detection:** Injects malicious origin payloads (`https://evil-attacker.com` and `null`) to expose dangerous Access-Control configurations and credential leakage.
4. **Session Cookie Security:** Audits cookies for missing `Secure`, `HttpOnly`, and `SameSite` attributes to prevent session hijacking and CSRF attacks.
5. **SSL/TLS Certificate Inspection:** Extracts and analyzes the server's SSL certificate to verify cryptographic validity and calculate days until expiration.
6. **Sensitive Directory Probing:** Actively checks for exposed internal configuration and backup files (e.g., `.env`, `.git/config`, `backup.zip`).
7. **Automated Reporting:** Exports detailed scan metrics into `.json` or `.csv` formats for data analysis and compliance tracking.

---

## 📂 Project Structure
```text
Automated-Web-Scanner/
├── scanner.py          # Core multithreaded scanning engine
├── targets.txt         # Input file for batch processing
├── requirements.txt    # Heavyweight project dependencies
└── README.md           # Documentation and usage guide
