# Sentinel

A modular command-line security assessment toolkit built with Python.

Sentinel is the flagship project of **Project Ascend**

The goal is to build a professional, modular security assessment toolkit while progressively learning Python, networking, software engineering, and artificial intelligence. Instead of creating many small practice projects, Sentinel evolves every week as I learn new concepts.

---

## Vision

Sentinel will allow a user to assess a domain or an IP address against a variety of security checks. Eventually, the application will support:

- **DNS Analysis**
- **TLS / SSL Configuration & Certificate Inspection**
- **Open Port Detection**
- **HTTP Security Headers & Web Technology Detection**
- **Email Security** (SPF, DKIM, DMARC)
- **AI-powered Security Summaries**

The project is inspired by common security assessment techniques and is designed as a learning platform rather than a commercial security scanner.

---

## Current Features (v0.1)

- Interactive command-line interface
- Target type selection (Domain or IP Address)
- User input acceptance and validation
- Selected target confirmation
- Modular project structure ready for future expansion

---

## Roadmap

### Phase 1 — Python Foundations

- [x] Interactive CLI
- [x] Target selection
- [ ] Assessment menu
- [ ] Project refactoring
- [ ] File-based target loading

### Phase 2 — Networking

- [ ] DNS resolution
- [ ] IP lookup
- [ ] Reverse DNS

### Phase 3 — HTTP Analysis

- [ ] HTTP requests
- [ ] Response headers
- [ ] Redirect detection
- [ ] Security header analysis

### Phase 4 — TLS / SSL

- [ ] Certificate inspection
- [ ] Expiration checks
- [ ] Supported TLS versions
- [ ] Cipher suite analysis

### Phase 5 — Port Scanning

- [ ] TCP port scanning
- [ ] Banner grabbing
- [ ] Service identification

### Phase 6 — Reporting

- [ ] JSON export
- [ ] CSV export
- [ ] HTML report generation

### Phase 7 — Artificial Intelligence

- [ ] AI-generated security summaries
- [ ] Suggested remediation guidance
- [ ] Executive report generation

---

## Technologies

- **Python**
- **Git**
- **GitHub**

> _Note: Additional technologies will be introduced as the project evolves._

---

## Project Structure

```text
projects/
└── sentinel/
    ├── main.py
    └── README.md
```
