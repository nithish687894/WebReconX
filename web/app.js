/**
 * WebReconX Frontend Controller
 * Implements premium cyber dark-mode interactions, connection detection,
 * progressive terminal simulator, and interactive data visualization.
 */

// Tab Switching - Hosting Blueprints
function switchDocTab(event, tabId) {
    const parent = event.currentTarget.closest('.tab-container');
    
    // Toggle active classes on tab headers
    parent.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
    
    // Toggle active classes on tab contents
    parent.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    const targetContent = parent.querySelector(`#${tabId}`);
    if (targetContent) {
        targetContent.classList.add('active');
    }
}

// Tab Switching - Security Recon Data
function switchReconTab(event, tabId) {
    const parent = event.currentTarget.closest('.recon-tabs-container');
    
    parent.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.currentTarget.classList.add('active');
    
    parent.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    
    const targetContent = document.getElementById(tabId);
    if (targetContent) {
        targetContent.classList.add('active');
    }
}

// Attach functions to window scope for inline onclick hooks
window.switchDocTab = switchDocTab;
window.switchReconTab = switchReconTab;

document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const targetDomainInput = document.getElementById('target-domain');
    const targetTimeoutInput = document.getElementById('target-timeout');
    const targetThreadsInput = document.getElementById('target-threads');
    
    const btnStartScan = document.getElementById('btn-start-scan');
    const btnCancelScan = document.getElementById('btn-cancel-scan');
    const btnClearTerminal = document.getElementById('btn-clear-terminal');
    
    const appModeBadge = document.getElementById('app-mode-badge');
    const appModeText = document.getElementById('app-mode-text');
    const terminalLogOutput = document.getElementById('terminal-log-output');
    
    const terminalProgressContainer = document.getElementById('terminal-progress-container');
    const terminalProgressFill = document.getElementById('terminal-progress-fill');
    const progressPercent = document.getElementById('progress-percent');
    const progressStepText = document.getElementById('progress-step-text');
    
    const securityReportCard = document.getElementById('security-report-card');
    
    // Module checkboxes
    const modHeaders = document.getElementById('mod-headers');
    const modSsl = document.getElementById('mod-ssl');
    const modTech = document.getElementById('mod-tech');
    const modPorts = document.getElementById('mod-ports');
    const modDns = document.getElementById('mod-dns');
    const modSubdomains = document.getElementById('mod-subdomains');
    const modWayback = document.getElementById('mod-wayback');
    
    // Report Widgets & Tables
    const gaugeHeadersContainer = document.getElementById('gauge-headers-container');
    const gaugeHeadersFill = document.getElementById('gauge-headers-fill');
    const headersGradeLabel = document.getElementById('headers-grade-label');
    const headersScoreLabel = document.getElementById('headers-score-label');
    
    const gaugeSslContainer = document.getElementById('gauge-ssl-container');
    const gaugeSslFill = document.getElementById('gauge-ssl-fill');
    const sslGradeLabel = document.getElementById('ssl-grade-label');
    const sslScoreLabel = document.getElementById('ssl-score-label');
    
    const metricDuration = document.getElementById('metric-duration');
    const metricPorts = document.getElementById('metric-ports');
    const metricSubdomains = document.getElementById('metric-subdomains');
    const metricUrls = document.getElementById('metric-urls');
    
    const tableHeadersBody = document.querySelector('#table-headers tbody');
    const tableSslBody = document.querySelector('#table-ssl tbody');
    const techBadgeContainer = document.getElementById('tech-badge-container');
    const tableDnsBody = document.querySelector('#table-dns tbody');
    const tableSubdomainsBody = document.querySelector('#table-subdomains tbody');
    const tablePortsBody = document.querySelector('#table-ports tbody');
    const tableWaybackBody = document.querySelector('#table-wayback tbody');
    
    let isScanning = false;
    let scanAborted = false;
    let isLiveBackend = false;
    let apiBaseUrl = ''; // Relative or explicit path
    
    // Circumference for stroke-dasharray (r=40 is ~251.3)
    const MAX_DASH = 251.3;

    // Detect Environment Mode
    async function checkBackendConnection() {
        writeLog('system', '<i class="fa-solid fa-signal"></i> Probing backend connection state...');
        try {
            const resp = await fetch('/api/health', { method: 'GET', timeout: 3000 }).catch(() => null);
            if (resp && resp.ok) {
                isLiveBackend = true;
                appModeBadge.className = 'badge mode-badge live-active';
                appModeText.textContent = 'Live API Active';
                writeLog('running', '<i class="fa-solid fa-bolt"></i> Live FastAPI Backend online. Performing REAL web penetration reconnaissance.');
            } else {
                setStaticMode();
            }
        } catch (e) {
            setStaticMode();
        }
    }

    function setStaticMode() {
        isLiveBackend = false;
        appModeBadge.className = 'badge mode-badge';
        appModeText.textContent = 'Showcase Mode';
        writeLog('system', '<i class="fa-solid fa-server"></i> FastAPI wrapper offline. Sandbox Showcase Mode loaded.');
    }

    // Helper: Print log to terminal console
    function writeLog(type, html) {
        const line = document.createElement('div');
        line.className = `log-line ${type}`;
        
        const timestamp = new Date().toLocaleTimeString();
        line.innerHTML = `<span class="font-mono text-dark" style="margin-right: 8px;">[${timestamp}]</span> ${html}`;
        
        terminalLogOutput.appendChild(line);
        terminalLogOutput.scrollTop = terminalLogOutput.scrollHeight;
    }

    // Clear Terminal Logs
    btnClearTerminal.addEventListener('click', () => {
        terminalLogOutput.innerHTML = `<div class="log-line system"><i class="fa-solid fa-info-circle"></i> Console cleared.</div>`;
    });

    // Helper: Grade to css classes
    function setGaugeStyle(container, fillElement, score, grade) {
        // Reset classes
        container.className = 'radial-gauge';
        
        let gradeClass = 'grade-f';
        const g = grade.toUpperCase();
        if (g.startsWith('A')) gradeClass = 'grade-a';
        else if (g.startsWith('B')) gradeClass = 'grade-b';
        else if (g.startsWith('C')) gradeClass = 'grade-c';
        else if (g.startsWith('D')) gradeClass = 'grade-d';
        
        container.classList.add(gradeClass);
        
        // Calculate offset
        const offset = MAX_DASH - (MAX_DASH * score / 100);
        fillElement.style.strokeDashoffset = offset;
    }

    // Generate Beautiful Mock Data for Static Sandbox Showcase
    function getMockData(domain) {
        // Generate realistic scores
        const hScore = Math.floor(Math.random() * 40) + 45; // 45 to 85
        let hGrade = 'F';
        if (hScore >= 80) hGrade = 'A';
        else if (hScore >= 70) hGrade = 'B';
        else if (hScore >= 60) hGrade = 'C';
        else if (hScore >= 50) hGrade = 'D';

        const sslScore = Math.floor(Math.random() * 20) + 80; // 80 to 100
        let sslGrade = 'A';
        if (sslScore < 90) sslGrade = 'B';

        const sanitizedDomain = domain.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];

        return {
            "duration": (Math.random() * 2.5 + 1.2).toFixed(2),
            "headers": {
                "status": "completed",
                "data": {
                    "score": hScore,
                    "grade": hGrade,
                    "present": {
                        "Strict-Transport-Security": {
                            "value": "max-age=31536000; includeSubDomains; preload",
                            "severity": "HIGH",
                            "desc": "Enforces HTTPS connections"
                        },
                        "X-Content-Type-Options": {
                            "value": "nosniff",
                            "severity": "MEDIUM",
                            "desc": "Blocks MIME-sniffing vulnerabilities"
                        },
                        "X-Frame-Options": {
                            "value": "SAMEORIGIN",
                            "severity": "MEDIUM",
                            "desc": "Blocks clickjacking scripts"
                        },
                        "Cache-Control": {
                            "value": "no-store, no-cache, must-revalidate",
                            "severity": "LOW",
                            "desc": "Controls client side data caching"
                        }
                    },
                    "missing": [
                        {
                            "header": "Content-Security-Policy",
                            "severity": "HIGH",
                            "desc": "Mitigates XSS injection vectors"
                        },
                        {
                            "header": "Permissions-Policy",
                            "severity": "MEDIUM",
                            "desc": "Disables unauthorized hardware integrations"
                        },
                        {
                            "header": "Referrer-Policy",
                            "severity": "LOW",
                            "desc": "Mitigates cross-domain metadata leakages"
                        }
                    ],
                    "leaks": [
                        {
                            "header": "Server",
                            "value": "nginx/1.24.0 (Ubuntu)"
                        },
                        {
                            "header": "X-Powered-By",
                            "value": "Next.js / React"
                        }
                    ]
                }
            },
            "ssl": {
                "status": "completed",
                "data": {
                    "score": sslScore,
                    "grade": sslGrade,
                    "protocol": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384 (256-bit)",
                    "subject": sanitizedDomain,
                    "issuer": "Let's Encrypt Authority X3",
                    "days_until_expiry": Math.floor(Math.random() * 85) + 5,
                    "san": [sanitizedDomain, `www.${sanitizedDomain}`, `api.${sanitizedDomain}`, `dev.${sanitizedDomain}`],
                    "issues": sslScore < 90 ? ["Weak legacy SHA-1 anchor verified in fallback path"] : [],
                    "info": [
                        `Protocol: TLSv1.3`,
                        `Cipher: TLS_AES_256_GCM_SHA384 (256-bit)`,
                        `Issuer: Let's Encrypt`,
                        `Certificate valid for more than 30 days`,
                        `SANs: ${sanitizedDomain}, www.${sanitizedDomain}`
                    ]
                }
            },
            "tech": {
                "status": "completed",
                "data": {
                    "detected": [
                        {"name": "Next.js", "category": "JS Framework"},
                        {"name": "React", "category": "JS Framework"},
                        {"name": "Tailwind CSS", "category": "CSS Framework"},
                        {"name": "Nginx", "category": "Web Server"},
                        {"name": "Cloudflare", "category": "CDN"},
                        {"name": "Google Analytics", "category": "Analytics"}
                    ]
                }
            },
            "dns": {
                "status": "completed",
                "data": {
                    "records": {
                        "A": ["104.21.72.48", "172.67.132.96"],
                        "AAAA": ["2606:4700:3030::ac43:8460", "2606:4700:3035::6815:4830"],
                        "MX": [`10 mail.${sanitizedDomain}`, `20 spool.${sanitizedDomain}`],
                        "NS": ["ns-cloud-c1.googledomains.com", "ns-cloud-c2.googledomains.com"],
                        "TXT": ["\"v=spf1 include:_spf.mx.cloudflare.net ~all\"", "\"google-site-verification=dH382910dKs9\""],
                        "CNAME": ["cname.cloudflare.net"],
                        "SOA": [`ns1.cloudflare.com. hostmaster.${sanitizedDomain}. 2026052501 7200 3600 1209600 3600`]
                    }
                }
            },
            "subdomains": {
                "status": "completed",
                "data": {
                    "subdomains": [
                        {"subdomain": `www.${sanitizedDomain}`, "ip": "104.21.72.48", "source": "crt.sh"},
                        {"subdomain": `api.${sanitizedDomain}`, "ip": "104.21.72.49", "source": "bruteforce"},
                        {"subdomain": `dev.${sanitizedDomain}`, "ip": "104.21.72.50", "source": "crt.sh"},
                        {"subdomain": `admin.${sanitizedDomain}`, "ip": "104.21.72.51", "source": "bruteforce"},
                        {"subdomain": `mail.${sanitizedDomain}`, "ip": "172.67.132.96", "source": "crt.sh"}
                    ]
                }
            },
            "ports": {
                "status": "completed",
                "data": {
                    "host": "104.21.72.48",
                    "open": [
                        {"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1", "risky": false},
                        {"port": 80, "service": "HTTP", "banner": "cloudflare-nginx", "risky": false},
                        {"port": 443, "service": "HTTPS", "banner": "cloudflare-nginx", "risky": false},
                        {"port": 8080, "service": "HTTP-Alt", "banner": "NodeExpress API Endpoint Server", "risky": false},
                        {"port": 3306, "service": "MySQL", "banner": "", "risky": true}
                    ]
                }
            },
            "wayback": {
                "status": "completed",
                "data": {
                    "total": 412,
                    "interesting": {
                        "config": [
                            `https://${sanitizedDomain}/.env`,
                            `https://${sanitizedDomain}/config.ini`,
                            `https://${sanitizedDomain}/database.yml`
                        ],
                        "backup": [
                            `https://${sanitizedDomain}/backup.tar.gz`,
                            `https://${sanitizedDomain}/dump_prod_2026.sql`
                        ],
                        "secrets": [
                            `https://${sanitizedDomain}/credentials.json`
                        ],
                        "admin": [
                            `https://${sanitizedDomain}/admin/login`,
                            `https://${sanitizedDomain}/dashboard/monitor`
                        ],
                        "api": [
                            `https://${sanitizedDomain}/api/v1/auth/session`,
                            `https://${sanitizedDomain}/api/v2/users/register`,
                            `https://${sanitizedDomain}/graphql`
                        ]
                    }
                }
            }
        };
    }

    // Trigger Scan Orchestrator
    async function startScan() {
        const domain = targetDomainInput.value.trim();
        if (!domain) {
            alert('Please specify a valid target domain / host IP.');
            return;
        }

        // Setup States
        isScanning = true;
        scanAborted = false;
        btnStartScan.disabled = true;
        btnCancelScan.classList.remove('hidden');
        securityReportCard.classList.add('hidden');
        
        terminalProgressContainer.classList.remove('hidden');
        terminalProgressFill.style.width = '0%';
        progressPercent.textContent = '0%';
        
        // Assemble requested modules
        const modules = [];
        if (modHeaders.checked) modules.push('headers');
        if (modSsl.checked) modules.push('ssl');
        if (modTech.checked) modules.push('tech');
        if (modPorts.checked) modules.push('ports');
        if (modDns.checked) modules.push('dns');
        if (modSubdomains.checked) modules.push('subdomains');
        if (modWayback.checked) modules.push('wayback');

        if (modules.length === 0) {
            alert('Select at least one reconnaissance module to scan.');
            stopScanning();
            return;
        }

        writeLog('system', `<i class="fa-solid fa-bullseye"></i> Targeting audit domain: <strong>${domain}</strong>`);
        writeLog('running', `<i class="fa-solid fa-circle-nodes"></i> Initiating scan queue with ${modules.length} active pipelines...`);

        if (isLiveBackend) {
            // ==========================================
            // LIVE BACKEND API SCAN
            // ==========================================
            try {
                // progressive terminal logs prior to API return
                let percentage = 0;
                const logInterval = setInterval(() => {
                    if (percentage < 90 && isScanning) {
                        percentage += Math.floor(Math.random() * 8) + 2;
                        terminalProgressFill.style.width = `${percentage}%`;
                        progressPercent.textContent = `${percentage}%`;
                        
                        // Fake progress steps to show active console processing
                        if (percentage < 20) {
                            progressStepText.textContent = "Resolving host subnets & WHOIS...";
                        } else if (percentage < 40) {
                            progressStepText.textContent = "Parsing SSL keys and cipher suites...";
                        } else if (percentage < 60) {
                            progressStepText.textContent = "Sniffing TCP handshakes and daemon banners...";
                        } else if (percentage < 80) {
                            progressStepText.textContent = "Querying Certificate Transparency registers...";
                        } else {
                            progressStepText.textContent = "Parsing Wayback historical endpoints...";
                        }
                    } else {
                        clearInterval(logInterval);
                    }
                }, 800);

                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target: domain,
                        modules: modules,
                        timeout: parseInt(targetTimeoutInput.value) || 10,
                        threads: parseInt(targetThreadsInput.value) || 10
                    })
                });

                clearInterval(logInterval);

                if (!response.ok) {
                    throw new Error(`HTTP network error: status ${response.status}`);
                }

                const resultData = await response.json();
                
                if (scanAborted) return;
                
                // End progress bar
                terminalProgressFill.style.width = '100%';
                progressPercent.textContent = '100%';
                progressStepText.textContent = 'Reconnaissance successfully finished!';
                
                writeLog('result-pass', '<i class="fa-solid fa-circle-check"></i> Raw scanning process completed. Organizing cyber assessment datasets.');
                renderResults(resultData, domain);

            } catch (err) {
                writeLog('result-fail', `<i class="fa-solid fa-triangle-exclamation"></i> Network request crashed: ${err.message}`);
                stopScanning();
            }
        } else {
            // ==========================================
            // SANDBOX SIMULATED RECONNAISSANCE SHOWCASE
            // ==========================================
            const delay = (ms) => new Promise(res => setTimeout(res, ms));
            
            // Loop through selected modules step by step
            const steps = [
                { id: 'dns', name: 'DNS Reconnaissance', emoji: '🌐', steps: ['Sending SOA queries...', 'Parsing DNS MX servers...', 'Resolving IPv4/IPv6 A record maps'] },
                { id: 'headers', name: 'Security Header Scanner', emoji: '🛡️', steps: ['HTTP GET to target root endpoint...', 'Checking security headers (HSTS, CSP, XFO)...', 'Scanning for server tech disclosure leaks'] },
                { id: 'ssl', name: 'SSL/TLS Analyzer', emoji: '🔑', steps: ['Opening socket pool on port 443...', 'Negotiating TLS 1.3 handshakes...', 'Extracting cert metadata and SAN chains'] },
                { id: 'tech', name: 'Technology Detector', emoji: '🧩', steps: ['Parsing cookie profiles...', 'Searching HTML signatures...', 'Fingerprinting frameworks & CMS versions'] },
                { id: 'ports', name: 'TCP Port Scanner', emoji: '🔌', steps: ['Scanning common ports...', 'Probing open endpoints...', 'Retrieving daemon banners'] },
                { id: 'subdomains', name: 'Subdomain Finder', emoji: '🕸️', steps: ['Querying crt.sh Certificate Transparency...', 'Starting dictionary subdomains resolves...', 'Filtering live endpoints'] },
                { id: 'wayback', name: 'Wayback Machine', emoji: '📜', steps: ['Querying Web Archive CDX API...', 'Scanning archived patterns for configs/backups...', 'Saving crawled URI endpoints'] }
            ];

            const mockFullData = getMockData(domain);
            let activeStepCount = 0;
            const totalSteps = modules.length;

            const filteredMockData = {
                duration: mockFullData.duration
            };

            for (const step of steps) {
                if (scanAborted) return;
                
                if (modules.includes(step.id)) {
                    activeStepCount++;
                    const percent = Math.floor((activeStepCount / totalSteps) * 100);
                    
                    terminalProgressFill.style.width = `${percent}%`;
                    progressPercent.textContent = `${percent}%`;
                    progressStepText.textContent = `Running module: ${step.name}...`;

                    writeLog('running', `${step.emoji} Starting: <strong>${step.name}</strong>`);
                    for (const subStep of step.steps) {
                        if (scanAborted) return;
                        await delay(Math.random() * 400 + 300);
                        writeLog('system', `  &gt;_ ${subStep}`);
                    }
                    
                    // Add mock output logs based on generated data
                    if (step.id === 'dns') {
                        const dnsRecs = mockFullData.dns.data.records;
                        writeLog('result-pass', `    Resolved A Records: ${dnsRecs.A.join(', ')}`);
                        writeLog('result-pass', `    Resolved MX Servers: ${dnsRecs.MX.join(', ')}`);
                    } else if (step.id === 'headers') {
                        writeLog('result-pass', `    Security Header Score: ${mockFullData.headers.data.score}/100 (Grade: ${mockFullData.headers.data.grade})`);
                        mockFullData.headers.data.missing.forEach(m => {
                            writeLog('result-warn', `    [MISSING] ${m.header} - Severity: ${m.severity}`);
                        });
                    } else if (step.id === 'ssl') {
                        writeLog('result-pass', `    SSL Protocol: ${mockFullData.ssl.data.protocol} | Cipher: ${mockFullData.ssl.data.cipher}`);
                        writeLog('result-pass', `    Issuer: ${mockFullData.ssl.data.issuer} | Expiry: ${mockFullData.ssl.data.days_until_expiry} days`);
                    } else if (step.id === 'tech') {
                        const techs = mockFullData.tech.data.detected.map(t => t.name).join(', ');
                        writeLog('result-pass', `    Technologies Identified: ${techs}`);
                    } else if (step.id === 'ports') {
                        const open = mockFullData.ports.data.open.map(p => p.port).join(', ');
                        writeLog('result-pass', `    Discovered Open TCP Ports: ${open}`);
                    } else if (step.id === 'subdomains') {
                        writeLog('result-pass', `    Discovered Subdomains: ${mockFullData.subdomains.data.subdomains.length} live records`);
                    } else if (step.id === 'wayback') {
                        writeLog('result-pass', `    Wayback Machine: Crawled ${mockFullData.wayback.data.total} historical URLs`);
                    }

                    // Copy to filtered final data
                    filteredMockData[step.id] = mockFullData[step.id];
                }
            }

            if (scanAborted) return;
            
            terminalProgressFill.style.width = '100%';
            progressPercent.textContent = '100%';
            progressStepText.textContent = 'Reconnaissance successfully finished!';
            
            writeLog('result-pass', '<i class="fa-solid fa-circle-check"></i> Simulation complete. Displaying glassmorphic visual report.');
            renderResults(filteredMockData, domain);
        }
    }

    // Abort active scan
    function abortScan() {
        scanAborted = true;
        writeLog('result-fail', '<i class="fa-solid fa-circle-xmark"></i> Scan execution aborted by operator.');
        stopScanning();
    }

    function stopScanning() {
        isScanning = false;
        btnStartScan.disabled = false;
        btnCancelScan.classList.add('hidden');
        terminalProgressContainer.classList.add('hidden');
    }

    // Render Data to Gauges and Tables
    function renderResults(res, domain) {
        stopScanning();

        // 1 - Show Visual Report Card
        securityReportCard.classList.remove('hidden');
        securityReportCard.scrollIntoView({ behavior: 'smooth' });

        // 2 - Duration
        metricDuration.textContent = `${res.duration || '1.50'}s`;

        // 3 - Reset Tables
        tableHeadersBody.innerHTML = '';
        tableSslBody.innerHTML = '';
        techBadgeContainer.innerHTML = '';
        tableDnsBody.innerHTML = '';
        tableSubdomainsBody.innerHTML = '';
        tablePortsBody.innerHTML = '';
        tableWaybackBody.innerHTML = '';

        // 4 - Populate Headers
        if (res.headers && res.headers.status === 'completed') {
            const hData = res.headers.data;
            headersScoreLabel.textContent = `${hData.score}/100`;
            headersGradeLabel.textContent = hData.grade;
            setGaugeStyle(gaugeHeadersContainer, gaugeHeadersFill, hData.score, hData.grade);

            // Present headers
            Object.entries(hData.present || {}).forEach(([name, meta]) => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono text-primary">${name}</td>
                    <td><span class="status-badge pass">Present</span></td>
                    <td><span class="status-badge low">Low</span></td>
                    <td class="text-main">${meta.desc || 'Configured correctly'}</td>
                `;
                tableHeadersBody.appendChild(tr);
            });

            // Missing headers
            (hData.missing || []).forEach(item => {
                const tr = document.createElement('tr');
                const sevClass = item.severity.toLowerCase();
                tr.innerHTML = `
                    <td class="font-mono alert-warning">${item.header}</td>
                    <td><span class="status-badge fail">Missing</span></td>
                    <td><span class="status-badge ${sevClass}">${item.severity}</span></td>
                    <td class="text-main">${item.desc || 'Missing security header'}</td>
                `;
                tableHeadersBody.appendChild(tr);
            });

            // Leaked headers
            (hData.leaks || []).forEach(leak => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono alert-critical">${leak.header}</td>
                    <td><span class="status-badge critical">Leak</span></td>
                    <td><span class="status-badge high">Medium</span></td>
                    <td class="text-main">Discloses daemon signature: <code>${leak.value}</code></td>
                `;
                tableHeadersBody.appendChild(tr);
            });
        } else {
            headersScoreLabel.textContent = '—';
            headersGradeLabel.textContent = 'F';
            setGaugeStyle(gaugeHeadersContainer, gaugeHeadersFill, 0, 'F');
            tableHeadersBody.innerHTML = '<tr><td colspan="4" class="text-center text-dark">Header analysis skipped or failed.</td></tr>';
        }

        // 5 - Populate SSL
        if (res.ssl && res.ssl.status === 'completed') {
            const sslData = res.ssl.data;
            
            // Calculate an SSL score for visual display (100 - 25 * count of issues)
            const computedSslScore = sslData.score !== undefined ? sslData.score : Math.max(0, 100 - (sslData.issues || []).length * 25);
            const computedSslGrade = sslData.grade !== undefined ? sslData.grade : (computedSslScore >= 95 ? 'A+' : (computedSslScore >= 80 ? 'A' : (computedSslScore >= 60 ? 'C' : 'F')));

            sslScoreLabel.textContent = `${computedSslScore}/100`;
            sslGradeLabel.textContent = computedSslGrade;
            setGaugeStyle(gaugeSslContainer, gaugeSslFill, computedSslScore, computedSslGrade);

            // General SSL parameters
            const props = [
                { key: 'Protocol Version', val: sslData.protocol || 'Unknown', status: (sslData.protocol && !sslData.protocol.includes('TLSv1.')) ? 'pass' : 'fail' },
                { key: 'Cipher Suite', val: sslData.cipher || 'Unknown', status: 'pass' },
                { key: 'Common Name (Subject)', val: sslData.subject || domain, status: 'pass' },
                { key: 'Issuer Organization', val: sslData.issuer || 'Unknown', status: 'pass' },
                { key: 'Days until Certificate Expiry', val: sslData.days_until_expiry !== undefined ? `${sslData.days_until_expiry} days` : 'N/A', status: (sslData.days_until_expiry > 15) ? 'pass' : 'fail' }
            ];

            props.forEach(p => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono">${p.key}</td>
                    <td class="text-main">${p.val}</td>
                    <td><span class="status-badge ${p.status}">${p.status === 'pass' ? 'Secure' : 'Warning'}</span></td>
                `;
                tableSslBody.appendChild(tr);
            });

            // Issues listed separately
            (sslData.issues || []).forEach(issue => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono alert-critical">Security Issue</td>
                    <td class="text-main">${issue}</td>
                    <td><span class="status-badge critical">Critical</span></td>
                `;
                tableSslBody.appendChild(tr);
            });
        } else {
            sslScoreLabel.textContent = '—';
            sslGradeLabel.textContent = 'F';
            setGaugeStyle(gaugeSslContainer, gaugeSslFill, 0, 'F');
            tableSslBody.innerHTML = '<tr><td colspan="3" class="text-center text-dark">SSL certificates analysis skipped.</td></tr>';
        }

        // 6 - Populate Tech Detector
        if (res.tech && res.tech.status === 'completed') {
            const tData = res.tech.data;
            const detected = tData.detected || [];
            
            if (detected.length === 0) {
                techBadgeContainer.innerHTML = '<div class="text-dark">No web technologies detected.</div>';
            } else {
                detected.forEach(t => {
                    const badge = document.createElement('div');
                    badge.className = 'tech-badge-item';

                    badge.innerHTML = `
                        <span class="tech-badge-name">${t.name}</span>
                        <span class="tech-badge-cat">${t.category}</span>
                    `;
                    techBadgeContainer.appendChild(badge);
                });
            }
        } else {
            techBadgeContainer.innerHTML = '<div class="text-dark">Technology Fingerprinting skipped.</div>';
        }

        // 7 - Populate DNS
        if (res.dns && res.dns.status === 'completed') {
            const dData = res.dns.data;
            const records = dData.records || {};
            let recordCount = 0;

            Object.entries(records).forEach(([type, vals]) => {
                (vals || []).forEach(val => {
                    recordCount++;
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td class="font-mono text-primary">${type}</td>
                        <td class="font-mono text-main">${val}</td>
                        <td class="text-dark">Auto (86400)</td>
                    `;
                    tableDnsBody.appendChild(tr);
                });
            });

            if (recordCount === 0) {
                tableDnsBody.innerHTML = '<tr><td colspan="3" class="text-center text-dark">No DNS records discovered.</td></tr>';
            }
        } else {
            tableDnsBody.innerHTML = '<tr><td colspan="3" class="text-center text-dark">DNS Reconnaissance skipped.</td></tr>';
        }

        // 8 - Populate Subdomains
        if (res.subdomains && res.subdomains.status === 'completed') {
            const sData = res.subdomains.data;
            const subs = sData.subdomains || [];
            metricSubdomains.textContent = subs.length;

            subs.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="font-mono text-primary">${s.subdomain}</td>
                    <td class="font-mono text-main">${s.ip || 'unresolved'}</td>
                    <td><span class="status-badge ${s.source === 'crt.sh' ? 'low' : 'medium'}">${s.source}</span></td>
                `;
                tableSubdomainsBody.appendChild(tr);
            });

            if (subs.length === 0) {
                tableSubdomainsBody.innerHTML = '<tr><td colspan="3" class="text-center text-dark">No subdomains found.</td></tr>';
            }
        } else {
            metricSubdomains.textContent = '0';
            tableSubdomainsBody.innerHTML = '<tr><td colspan="3" class="text-center text-dark">Subdomains Discovery skipped.</td></tr>';
        }

        // 9 - Populate Ports
        if (res.ports && res.ports.status === 'completed') {
            const pData = res.ports.data;
            const open = pData.open || [];
            metricPorts.textContent = open.length;

            open.forEach(p => {
                const tr = document.createElement('tr');
                const bannerText = p.banner ? p.banner : '<span class="text-dark">No handshake response</span>';
                tr.innerHTML = `
                    <td class="font-mono text-primary">${p.port}</td>
                    <td class="font-mono">${p.service}</td>
                    <td class="font-mono text-main">${bannerText}</td>
                    <td><span class="status-badge ${p.risky ? 'critical' : 'pass'}">${p.risky ? 'RISKY' : 'SAFE'}</span></td>
                `;
                tablePortsBody.appendChild(tr);
            });

            if (open.length === 0) {
                tablePortsBody.innerHTML = '<tr><td colspan="4" class="text-center text-dark">No open TCP ports found in typical scanner range.</td></tr>';
            }
        } else {
            metricPorts.textContent = '0';
            tablePortsBody.innerHTML = '<tr><td colspan="4" class="text-center text-dark">Port Scanner skipped.</td></tr>';
        }

        // 10 - Populate Wayback
        if (res.wayback && res.wayback.status === 'completed') {
            const wData = res.wayback.data;
            const totalArchived = wData.total || 0;
            const interesting = wData.interesting || {};
            metricUrls.textContent = totalArchived;
            let interestingCount = 0;

            Object.entries(interesting).forEach(([category, urls]) => {
                (urls || []).forEach(url => {
                    interestingCount++;
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><span class="status-badge ${category === 'secrets' || category === 'backup' ? 'critical' : 'medium'}">${category}</span></td>
                        <td class="font-mono text-main" style="max-width: 450px; overflow: hidden; text-overflow: ellipsis;"><a href="${url}" target="_blank" class="text-main" style="text-decoration:none;">${url}</a></td>
                    `;
                    tableWaybackBody.appendChild(tr);
                });
            });

            if (interestingCount === 0) {
                tableWaybackBody.innerHTML = '<tr><td colspan="2" class="text-center text-dark">No critical archived endpoints matched rules.</td></tr>';
            }
        } else {
            metricUrls.textContent = '0';
            tableWaybackBody.innerHTML = '<tr><td colspan="2" class="text-center text-dark">Wayback Machine fetch skipped.</td></tr>';
        }
    }

    // Attach Click Events
    btnStartScan.addEventListener('click', startScan);
    btnCancelScan.addEventListener('click', abortScan);

    // Initial check on backend health
    checkBackendConnection();
});
