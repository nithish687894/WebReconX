<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=venom&color=00ff88&height=180&section=header&text=WebReconX&fontSize=70&fontColor=ffffff&animation=twinkling&desc=Advanced%20Web%20Security%20Reconnaissance%20Framework&descSize=20&descAlignY=75&descColor=00ff88" width="100%"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-00ff88?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-333333?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-ff6633?style=for-the-badge"/>
</p>

<p align="center">
  <b>A powerful, modular web security reconnaissance framework that combines 7 scanning modules into a single command-line tool.</b>
</p>

---

## Features

WebReconX performs comprehensive security reconnaissance with these built-in modules:

| Module | Description |
|--------|-------------|
| **Security Headers** | Analyzes 11 HTTP security headers, scores configuration, detects info leaks |
| **SSL/TLS Analyzer** | Checks certificate validity, protocol versions, cipher strength, expiry |
| **Tech Detector** | Identifies 50+ web technologies, frameworks, CMS, CDN, and analytics |
| **Port Scanner** | Multi-threaded scan of 29 common ports with banner grabbing and risk assessment |
| **DNS Recon** | Enumerates A, AAAA, MX, NS, TXT, CNAME, SOA records using raw DNS queries |
| **Subdomain Finder** | Discovers subdomains via Certificate Transparency (crt.sh) and DNS bruteforce |
| **Wayback Fetcher** | Retrieves historical URLs, finds interesting files, API endpoints, and forgotten paths |

### Key Highlights

- **Zero external dependencies** for core scanning (only `requests` library needed)
- **Raw DNS implementation** - custom DNS query builder and parser (no `dnspython` needed)
- **Multi-threaded scanning** for ports and subdomains
- **Security scoring** with letter grades for headers and SSL
- **JSON report export** for integration with other tools
- **Professional terminal UI** with color-coded severity levels
- **Modular architecture** - easily extendable with new modules
- **Premium Glassmorphic Web Dashboard** - a state-of-the-art SOC-style interface featuring live circular risk gauges, search tables, custom threads/timeouts, and dynamic progress logger consoles.

---

## ⚡ Premium Web Dashboard

WebReconX now comes equipped with an ultra-premium, responsive, **glassmorphic security auditing dashboard** designed in a cyber dark-slate theme:

- **Dual-Mode System**:
  1. **Sandbox Showcase (Client-side)**: Runs fully serverless in the browser, simulating high-fidelity scans on any domain. Deployable instantly for **free** on **Vercel** or **GitHub Pages**.
  2. **Active Full-Stack Scanner (FastAPI)**: Integrates directly with the Python scanning engine to run real active scans over public HTTP/DNS/SSL registers. Hostable for **free** on **Render**.
- **Interactive Radial Gauges**: Real-time calculated security ratings (A+ through F) with SVG stroke tracking.
- **Searchable Recon Datagrids**: Clean tabular tabs for all 7 reconnaissance pipelines.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/nithish687894/WebReconX.git
cd WebReconX

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

### Full Scan (all modules)

```bash
python webreconx.py example.com
```

### Run Specific Modules

```bash
# Security headers and SSL only
python webreconx.py example.com -m headers ssl

# Port scan with custom timeout
python webreconx.py example.com -m ports -t 5

# Subdomain enumeration
python webreconx.py example.com -m subdomains

# Technology detection and Wayback Machine
python webreconx.py example.com -m tech wayback
```

### Save Report

```bash
python webreconx.py example.com -o report.json
```

### List All Modules

```bash
python webreconx.py --list-modules
```

### Help

```bash
python webreconx.py -h
```

---

## 🖥️ Running & Deploying the Web Dashboard

### Local Execution (FastAPI active scan server)
Start the lightweight web API wrapper on your local machine to trigger live interactive scans directly from the browser:

```bash
# Start the FastAPI uvicorn daemon
python web/server.py
```
Open your browser of choice and direct it to **`http://localhost:8000`** to experience the premium cybersecurity operations console.

---

### Cloud Hosting Blueprints

#### 1. Live Active Scans on Render (Recommended)
This repository includes a `render.yaml` specification designed to run seamlessly on the **Render Free tier (`plan: free`)**, skipping any credit card validation blockades:
- Register/Login on [Render.com](https://render.com).
- Click **New** in the top right > **Blueprint**.
- Connect your `WebReconX` GitHub repository.
- Name the deployment and click **Approve/Deploy**. Render will automatically detect the blueprints, build python, install packages, and deploy the FastAPI daemon.

#### 2. Vercel Static Showcase (Serverless)
Deploy the visual sandbox as a client-side showcase:
```bash
# Using Vercel CLI (zero config)
vercel
```
Vercel reads the root `vercel.json` routing configuration and instantly hosts the serverless dashboard on Vercel's Edge network.

#### 3. GitHub Pages CI/CD
We've bundled an automated GitHub Actions deployment workflow at `.github/workflows/deploy.yml`:
- Navigate to your repository settings on GitHub.
- Go to **Settings** > **Pages**.
- Change the Source to **GitHub Actions**.
- On every git push to your `main` branch, the workflow compiles and hosts the showcase dashboard at `https://<your-username>.github.io/WebReconX/` automatically.

---

## Output Example

```
 ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
 ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
 ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
 ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
  ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

    [i] Target    : https://example.com
    [i] Modules   : 7
    [i] Started   : 2026-02-15 12:00:00

  ┌────────────────────────────────────────────────────────────────┐
  │ ▶ Security Header Scanner                                      │
  └────────────────────────────────────────────────────────────────┘

    [✓] Strict-Transport-Security: max-age=31536000
    [✓] X-Content-Type-Options: nosniff
    [HIGH] Content-Security-Policy - Prevents XSS, clickjacking
    [MEDIUM] Permissions-Policy - Controls browser feature permissions

    [i] Security Score: 65/100 (Grade: C)
```

---

## Project Structure

```
WebReconX/
├── webreconx.py              # Main entry point & CLI
├── requirements.txt           # Python dependencies
├── .gitignore                 # Git ignore rules
├── README.md                  # Documentation
├── LICENSE                    # MIT License
├── modules/
│   ├── __init__.py
│   ├── base_scanner.py        # Abstract base class for all modules
│   ├── header_scanner.py      # HTTP security header analysis
│   ├── ssl_analyzer.py        # SSL/TLS certificate & config check
│   ├── tech_detector.py       # Web technology fingerprinting
│   ├── port_scanner.py        # Multi-threaded port scanner
│   ├── dns_recon.py           # Raw DNS record enumeration
│   ├── subdomain_finder.py    # Subdomain discovery (crt.sh + DNS)
│   ├── wayback_fetcher.py     # Wayback Machine URL retrieval
│   └── report_generator.py    # JSON report generation
├── utils/
│   ├── __init__.py
│   ├── colors.py              # ANSI color utilities
│   └── banner.py              # Terminal output formatting
└── wordlists/
    └── (custom wordlists)
```

---

## Modules In Depth

### Security Header Scanner

Checks for 11 critical security headers based on OWASP recommendations and assigns a security grade (A+ to F). Also detects information disclosure through headers like `Server` and `X-Powered-By`.

### SSL/TLS Analyzer

Performs comprehensive SSL analysis including certificate validation, expiry checking, protocol version detection (flags deprecated TLS 1.0/1.1), cipher strength assessment, and self-signed certificate detection.

### Technology Detector

Identifies 50+ technologies by analyzing HTTP headers, HTML content patterns, meta tags, and cookies. Categories include CMS platforms, JavaScript frameworks, frontend libraries, analytics tools, CDN providers, and security solutions.

### Port Scanner

Multi-threaded scanner that checks 29 common ports with service identification and banner grabbing. Flags security-risky ports (like exposed databases, RDP, or Redis) with specific warnings.

### DNS Reconnaissance

Custom-built DNS query engine (no external DNS libraries) that constructs and parses raw DNS packets. Enumerates A, AAAA, MX, NS, TXT, CNAME, and SOA records for complete domain intelligence.

### Subdomain Finder

Combines two discovery methods: Certificate Transparency logs via crt.sh API and DNS bruteforce using a curated wordlist of 100+ common subdomains. Results include IP resolution and source attribution.

### Wayback Machine Fetcher

Queries the Wayback Machine CDX API to discover historical URLs, interesting files (configs, backups, source code), API endpoints, and forgotten paths. Categorizes findings by file type and security relevance.

---

## Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Always obtain proper authorization before scanning any target. Unauthorized scanning may be illegal in your jurisdiction. The author is not responsible for any misuse of this tool.

---

## Author

**NithishKumar S** — National CTF Finalist | Web Exploitation Specialist

- GitHub: [@nithish687894](https://github.com/nithish687894)
- Portfolio: [nithish687894.github.io](https://nithish687894.github.io/nitx1sh.github.io/)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <img src="https://capsule-render.vercel.app/api?type=waving&color=00ff88&height=100&section=footer" width="100%"/>
</p>
