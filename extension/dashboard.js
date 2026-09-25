async function initDashboard() {
    // Dynamic API Base URL (works both in local Chrome extension and cloud/tunnel deployments)
    const API_BASE = (window.location.protocol.startsWith('http') && !window.location.origin.includes('chrome-extension'))
        ? window.location.origin
        : 'http://127.0.0.1:8000';

    // --- Navigation Logic ---
    const navItems = {
        'nav-dashboard': 'section-dashboard',
        'nav-scanner': 'section-scanner',
        'nav-forensics': 'section-forensics',
        'nav-cases': 'section-cases',
        'nav-threat-intel': 'section-threat-intel',
        'nav-settings': 'section-settings'
    };

    function switchSection(activeNavId) {
        Object.keys(navItems).forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.remove('active');
        });
        const activeNav = document.getElementById(activeNavId);
        if (activeNav) activeNav.classList.add('active');

        Object.values(navItems).forEach(sectionId => {
            const sec = document.getElementById(sectionId);
            if (sec) sec.style.display = 'none';
        });
        const activeSection = document.getElementById(navItems[activeNavId]);
        if (activeSection) activeSection.style.display = 'block';

        if (activeNavId === 'nav-cases') {
            loadCasesAndCampaigns();
        }
    }

    Object.keys(navItems).forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            el.addEventListener('click', () => switchSection(id));
        }
    });

    // Check URL parameters (e.g. ?section=scanner or ?section=forensics)
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('section') === 'scanner') {
        switchSection('nav-scanner');
    } else if (urlParams.get('section') === 'forensics') {
        switchSection('nav-forensics');
    } else if (urlParams.get('section') === 'cases') {
        switchSection('nav-cases');
    }

    // --- Dark Mode Logic ---
    const darkModeToggle = document.getElementById('dark-mode-toggle');
    const isDarkMode = localStorage.getItem('darkMode') === 'true';
    
    if (isDarkMode && darkModeToggle) {
        document.body.classList.add('dark-mode');
        darkModeToggle.checked = true;
    }

    if (darkModeToggle) {
        darkModeToggle.addEventListener('change', (e) => {
            if (e.target.checked) {
                document.body.classList.add('dark-mode');
                localStorage.setItem('darkMode', 'true');
            } else {
                document.body.classList.remove('dark-mode');
                localStorage.setItem('darkMode', 'false');
            }
        });
    }

    // --- Fetch Dashboard Stats & Threat Intel ---
    async function fetchStatsAndHistory() {
        try {
            const response = await fetch(`${API_BASE}/api/dashboard/stats`);
            if (response.ok) {
                const data = await response.json();
                
                // Update Stats Cards
                document.getElementById('stat-total').textContent = data.stats.total_analyzed;
                document.getElementById('stat-phishing').textContent = data.stats.phishing_detected;
                document.getElementById('stat-suspicious').textContent = data.stats.suspicious_detected;
                document.getElementById('stat-safe').textContent = data.stats.safe_detected;
                
                // Update Dashboard Table
                const tbody = document.getElementById('history-body');
                const intelBody = document.getElementById('intel-body');
                tbody.innerHTML = '';
                intelBody.innerHTML = '';
                
                let threatIntelCount = 0;

                if (data.recent_activity.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="5">No security events recorded yet.</td></tr>';
                    intelBody.innerHTML = '<tr><td colspan="3">No URLs have been analyzed yet.</td></tr>';
                } else {
                    data.recent_activity.forEach(log => {
                        const date = new Date(log.timestamp).toLocaleString();
                        const verdictClean = (log.verdict || '').toLowerCase().replace('likely ', '');
                        const badgeClass = `badge-${verdictClean}`;
                        const displayVerdict = verdictClean === 'safe' ? 'LEGITIMATE' : verdictClean.toUpperCase();
                        
                        // Main Dashboard Table
                        const tr = document.createElement('tr');
                        tr.innerHTML = `
                            <td>${date}</td>
                            <td><strong>${log.item_type}</strong></td>
                            <td>${log.target}</td>
                            <td><span class="badge ${badgeClass}">${displayVerdict}</span></td>
                            <td>${log.action_taken}</td>
                        `;
                        tbody.appendChild(tr);

                        // Threat Intel Table (Filter for URLs)
                        if (log.item_type === 'URL' && log.verdict !== 'safe' && log.verdict !== 'legitimate') {
                            threatIntelCount++;
                            const intelTr = document.createElement('tr');
                            intelTr.innerHTML = `
                                <td>${date}</td>
                                <td>${log.target}</td>
                                <td><span class="badge ${badgeClass}">${displayVerdict}</span></td>
                            `;
                            intelBody.appendChild(intelTr);
                        }
                    });

                    if (threatIntelCount === 0) {
                        intelBody.innerHTML = '<tr><td colspan="3">No malicious URLs detected recently.</td></tr>';
                    }
                }
            } else {
                document.getElementById('history-body').innerHTML = '<tr><td colspan="5">Failed to fetch data from backend.</td></tr>';
            }
        } catch (error) {
            console.error("Dashboard error:", error);
            document.getElementById('history-body').innerHTML = `<tr><td colspan="5">Backend server is offline or unreachable at ${API_BASE}.</td></tr>`;
        }
    }

    fetchStatsAndHistory();

    const refreshBtn = document.getElementById('btn-refresh-stats');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            fetchStatsAndHistory();
        });
    }

    // --- Settings & API Key ---
    async function fetchSettings() {
        try {
            const res = await fetch(`${API_BASE}/api/settings`);
            if (res.ok) {
                const data = await res.json();
                const banner = document.getElementById('intel-status-banner');
                const keyInput = document.getElementById('vt-api-key');
                if (data.vt_key_configured) {
                    if (keyInput) keyInput.placeholder = "•••••••••••••••••••••••• (Configured)";
                    if (banner) {
                        banner.innerHTML = '✅ VirusTotal API is configured and actively scanning URLs.';
                        banner.style.backgroundColor = '#e8f5e9';
                        banner.style.borderColor = '#4caf50';
                        banner.style.color = '#2e7d32';
                    }
                } else {
                    if (banner) {
                        banner.innerHTML = '⚠️ VirusTotal API key is missing. Threat Intel is disabled.';
                        banner.style.backgroundColor = '#fff8e1';
                        banner.style.borderColor = '#ffb300';
                        banner.style.color = '#ff8f00';
                    }
                }
            }
        } catch (e) {
            console.error("Settings error:", e);
        }
    }

    fetchSettings();

    const saveSettingsBtn = document.getElementById('save-settings-btn');
    if (saveSettingsBtn) {
        saveSettingsBtn.addEventListener('click', async () => {
            const apiKey = document.getElementById('vt-api-key').value;
            const statusMsg = document.getElementById('settings-status');
            
            if (!apiKey) {
                statusMsg.textContent = "Please enter an API key.";
                statusMsg.className = "status-msg error";
                return;
            }

            try {
                const res = await fetch(`${API_BASE}/api/settings`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ vt_api_key: apiKey })
                });

                if (res.ok) {
                    statusMsg.textContent = "API Key saved successfully!";
                    statusMsg.className = "status-msg success";
                    document.getElementById('vt-api-key').value = "";
                    fetchSettings();
                } else {
                    statusMsg.textContent = "Failed to save API key.";
                    statusMsg.className = "status-msg error";
                }
            } catch (e) {
                statusMsg.textContent = "Error connecting to backend.";
                statusMsg.className = "status-msg error";
            }
        });
    }

    // =========================================================================
    // --- EMAIL & ATTACHMENT SCANNER LOGIC ---
    // =========================================================================

    const senderNameInput = document.getElementById('scan-sender-name');
    const senderEmailInput = document.getElementById('scan-sender-email');
    const subjectInput = document.getElementById('scan-subject');
    const bodyInput = document.getElementById('scan-body');
    const linksInput = document.getElementById('scan-links');
    const attachmentsInput = document.getElementById('scan-attachments');
    const fileUploadInput = document.getElementById('scan-file-upload');
    const fileUploadInfo = document.getElementById('file-upload-info');
    const btnRunScan = document.getElementById('btn-run-scan');
    const btnClearScan = document.getElementById('btn-clear-scan');

    // Track chosen file
    let uploadedFile = null;
    if (fileUploadInput) {
        fileUploadInput.addEventListener('change', (e) => {
            if (e.target.files && e.target.files.length > 0) {
                uploadedFile = e.target.files[0];
                fileUploadInfo.textContent = `Selected: ${uploadedFile.name} (${(uploadedFile.size / 1024).toFixed(1)} KB)`;
                
                // Add filename to attachments input if not already present
                const current = attachmentsInput.value.trim();
                const list = current ? current.split(',').map(s => s.trim()) : [];
                if (!list.includes(uploadedFile.name)) {
                    list.push(uploadedFile.name);
                    attachmentsInput.value = list.join(', ');
                }
            } else {
                uploadedFile = null;
                fileUploadInfo.textContent = '';
            }
        });
    }

    // Presets
    const presets = {
        legit: {
            senderName: "Placement Cell Notice",
            senderEmail: "placement@university.edu",
            subject: "Schedule for Campus Placement Drives & Semester Examinations",
            body: "Dear Students,\n\nPlease find the schedule for the upcoming campus recruitment drives and semester examination timetable attached for your reference. All sessions will be held as per the regular academic calendar. Please ensure your project reports are submitted before the deadline.",
            links: "https://university.edu/student-portal",
            attachments: "semester_timetable.pdf, project_guidelines.docx"
        },
        phish: {
            senderName: "PayPal Security Center",
            senderEmail: "service-security@paypal-verification-alert.com",
            subject: "URGENT: Your account has been suspended! Immediate action required",
            body: "URGENT: We detected unauthorized login attempts to your PayPal account from an unrecognized IP address. To prevent permanent suspension and deactivation, you must verify your identity and update your billing credentials immediately within 24 hours.",
            links: "http://192.168.1.102/paypal-login/auth.php, http://test-phish.com",
            attachments: ""
        },
        att: {
            senderName: "Global Logistics Billing",
            senderEmail: "accounts@freight-invoicing-global.com",
            subject: "Overdue Invoice Payment Receipt #INV-99482",
            body: "Hello,\n\nPlease find attached the outstanding payment receipt and invoice document for your recent shipment services. Remit the balance to avoid legal action.",
            links: "",
            attachments: "invoice_receipt.pdf.exe, transaction_summary.pdf"
        },
        macro: {
            senderName: "Corporate Treasury",
            senderEmail: "wire-remittance@chase-banking-support.net",
            subject: "Wire Transfer Remittance Advice and Fee Calculator",
            body: "Immediate Action Required: Wire transfer of $14,500 is pending. Please open the attached spreadsheet and enable macros to execute the automated fee verification formula.",
            links: "http://fake-login.com/wire-auth",
            attachments: "wire_remittance_advice.xlsm"
        }
    };

    function applyPreset(data) {
        senderNameInput.value = data.senderName;
        senderEmailInput.value = data.senderEmail;
        subjectInput.value = data.subject;
        bodyInput.value = data.body;
        linksInput.value = data.links;
        attachmentsInput.value = data.attachments;
        if (fileUploadInput) fileUploadInput.value = '';
        uploadedFile = null;
        if (fileUploadInfo) fileUploadInfo.textContent = '';
    }

    const btnPresetLegit = document.getElementById('btn-preset-legit');
    if (btnPresetLegit) btnPresetLegit.addEventListener('click', () => applyPreset(presets.legit));

    const btnPresetPhish = document.getElementById('btn-preset-phish');
    if (btnPresetPhish) btnPresetPhish.addEventListener('click', () => applyPreset(presets.phish));

    const btnPresetAtt = document.getElementById('btn-preset-att');
    if (btnPresetAtt) btnPresetAtt.addEventListener('click', () => applyPreset(presets.att));

    const btnPresetMacro = document.getElementById('btn-preset-macro');
    if (btnPresetMacro) btnPresetMacro.addEventListener('click', () => applyPreset(presets.macro));

    if (btnClearScan) {
        btnClearScan.addEventListener('click', () => {
            senderNameInput.value = '';
            senderEmailInput.value = '';
            subjectInput.value = '';
            bodyInput.value = '';
            linksInput.value = '';
            attachmentsInput.value = '';
            if (fileUploadInput) fileUploadInput.value = '';
            uploadedFile = null;
            if (fileUploadInfo) fileUploadInfo.textContent = '';
            document.getElementById('result-details').style.display = 'none';
            document.getElementById('result-placeholder').style.display = 'block';
        });
    }

    // Execute Email & Attachment Scan
    if (btnRunScan) {
        btnRunScan.addEventListener('click', async () => {
            const senderName = senderNameInput.value.trim() || 'Unknown Sender';
            const senderEmail = senderEmailInput.value.trim() || 'unknown@example.com';
            const subject = subjectInput.value.trim();
            const body = bodyInput.value.trim();
            
            if (!subject && !body && !attachmentsInput.value.trim() && !uploadedFile) {
                alert("Please provide email text, subject, or attachments to analyze.");
                return;
            }

            // Parse links
            const rawLinks = linksInput.value.trim();
            const links = rawLinks ? rawLinks.split(/[,\n]/).map(s => s.trim()).filter(Boolean) : [];

            // Parse attachments
            const rawAtt = attachmentsInput.value.trim();
            const attachments = rawAtt ? rawAtt.split(/[,\n]/).map(s => s.trim()).filter(Boolean) : [];

            // Loading state
            btnRunScan.disabled = true;
            btnRunScan.textContent = "⏳ Analyzing Email & Attachments...";

            let fileAnalysisResult = null;

            try {
                // If a real file was uploaded, analyze its binary headers & hash first
                if (uploadedFile) {
                    const formData = new FormData();
                    formData.append('file', uploadedFile);
                    try {
                        const fileRes = await fetch(`${API_BASE}/api/analyze/attachment`, {
                            method: "POST",
                            body: formData
                        });
                        if (fileRes.ok) {
                            fileAnalysisResult = await fileRes.json();
                        }
                    } catch (fe) {
                        console.warn("Direct file upload analysis failed:", fe);
                    }
                }

                // Analyze full email (Text + Attachments + URLs)
                const payload = {
                    sender_name: senderName,
                    sender_email: senderEmail,
                    subject: subject,
                    body: body,
                    links: links,
                    attachments: attachments,
                    is_authenticated: true
                };

                const res = await fetch(`${API_BASE}/api/analyze/email`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload)
                });

                if (!res.ok) throw new Error("HTTP error " + res.status);
                const data = await res.json();

                // Merge real file upload indicators if present
                if (fileAnalysisResult) {
                    if (fileAnalysisResult.indicators && fileAnalysisResult.indicators.length > 0) {
                        fileAnalysisResult.indicators.forEach(ind => {
                            if (!data.indicators.some(i => i.description === ind.description)) {
                                data.indicators.unshift(ind);
                            }
                        });
                    }
                    if (fileAnalysisResult.verdict === 'phishing') {
                        data.verdict = 'phishing';
                        data.risk_category = 'High Risk';
                        data.explanation = fileAnalysisResult.explanation;
                    }
                }

                renderScanResult(data, fileAnalysisResult);
                fetchStatsAndHistory(); // Refresh recent logs

            } catch (err) {
                console.error("Scan error:", err);
                alert("Error connecting to backend server: " + err.message + ". Make sure the Python server is running.");
            } finally {
                btnRunScan.disabled = false;
                btnRunScan.textContent = "🚀 Scan Email & Attachments";
            }
        });
    }

    function renderScanResult(data, fileResult) {
        document.getElementById('result-placeholder').style.display = 'none';
        const detailsContainer = document.getElementById('result-details');
        detailsContainer.style.display = 'block';

        const verdict = (data.verdict || 'safe').toLowerCase();
        const isPhishing = verdict === 'phishing';
        const isSuspicious = verdict === 'suspicious';
        const isLegit = verdict === 'legitimate' || verdict === 'safe';

        const banner = document.getElementById('res-verdict-banner');
        const iconEl = document.getElementById('res-verdict-icon');
        const textEl = document.getElementById('res-verdict-text');
        const riskEl = document.getElementById('res-risk-badge');
        const expEl = document.getElementById('res-explanation');

        banner.className = 'verdict-banner';

        if (isPhishing) {
            banner.classList.add('verdict-banner-phishing');
            iconEl.textContent = '🚨';
            textEl.textContent = 'PHISHING DETECTED';
            riskEl.textContent = data.risk_category || 'HIGH RISK';
        } else if (isSuspicious) {
            banner.classList.add('verdict-banner-suspicious');
            iconEl.textContent = '⚠️';
            textEl.textContent = 'SUSPICIOUS';
            riskEl.textContent = data.risk_category || 'MEDIUM RISK';
        } else {
            banner.classList.add('verdict-banner-legitimate');
            iconEl.textContent = '🛡️';
            textEl.textContent = 'LEGITIMATE EMAIL';
            riskEl.textContent = 'LOW RISK - SAFE';
        }

        expEl.textContent = data.explanation;

        // Card 1: Text & AI NLP Analysis
        const textCard = document.getElementById('res-text-content');
        let textSummary = '';
        if (isLegit) {
            textSummary = `
                <p>✅ <strong>Status:</strong> Legitimate content patterns.</p>
                <p>No high-pressure urgency, malicious phishing lures, or spoofed brand names identified.</p>
            `;
        } else if (isPhishing) {
            textSummary = `
                <p>🚨 <strong>Status:</strong> Phishing indicators detected in email text.</p>
                <p>High-urgency language, brand spoofing, or deceptive intent detected by AI NLP engine.</p>
            `;
        } else {
            textSummary = `
                <p>⚠️ <strong>Status:</strong> Suspicious pattern detected.</p>
                <p>Contains potential marketing pressure or unverified sender characteristics.</p>
            `;
        }
        textCard.innerHTML = textSummary;

        // Card 2: Attachment Security Inspection
        const attCard = document.getElementById('res-attachment-content');
        let attHtml = '';

        const attachments = data.attachments_analyzed || [];
        if (attachments.length === 0 && !fileResult) {
            attHtml = '<p style="color:#64748b;">📎 No attachments were provided in this scan.</p>';
        } else {
            attachments.forEach(att => {
                let pillClass = 'att-scan-safe';
                let pillLabel = 'Safe Format';
                if (att.status === 'phishing') {
                    pillClass = 'att-scan-phish';
                    pillLabel = `🚨 DANGEROUS (${att.threat_type || 'Malware'})`;
                } else if (att.status === 'suspicious') {
                    pillClass = 'att-scan-susp';
                    pillLabel = `⚠️ Warning (${att.threat_type || 'Risk'})`;
                }
                attHtml += `
                    <div class="att-scan-row">
                        <div>
                            <div class="att-scan-name">📎 ${att.filename}</div>
                            <div style="font-size:11.5px;color:#64748b;">${att.details || ''}</div>
                        </div>
                        <span class="att-scan-pill ${pillClass}">${pillLabel}</span>
                    </div>
                `;
            });

            if (fileResult) {
                attHtml += `
                    <div style="margin-top:10px;padding-top:8px;border-top:1px dashed #cbd5e1;font-size:11.5px;color:#0284c7;">
                        <strong>Binary File Inspection:</strong> ${fileResult.detected_type || 'File analyzed'} | SHA-256: <code>${fileResult.sha256 ? fileResult.sha256.substring(0, 16) + '...' : 'N/A'}</code>
                    </div>
                `;
            }
        }
        attCard.innerHTML = attHtml;

        // Card 3: Indicators List
        const indicatorsList = document.getElementById('res-indicators-list');
        indicatorsList.innerHTML = '';
        if (data.indicators && data.indicators.length > 0) {
            data.indicators.forEach(ind => {
                const li = document.createElement('li');
                li.innerHTML = `<strong>[${ind.type}]</strong> ${ind.description}`;
                indicatorsList.appendChild(li);
            });
        } else {
            indicatorsList.innerHTML = '<li>No threat indicators triggered. Passed all security heuristic checks.</li>';
        }

        // Card 4: Action Recommendation
        document.getElementById('res-action-text').textContent = data.recommended_action;
    }

    // =========================================================================
    // PHASE 5 & 6: FORENSIC LAB, THREAT GRAPH & CASE CONTROLLERS
    // =========================================================================
    const FORENSIC_API_KEY = "pg-forensic-secret-key-change-me-in-production";
    let lastForensicResult = null;
    let lastForensicRawText = "";

    // EML Preset Fixtures
    const EML_PRESETS = {
        legit: `Received: from mail.company.com (mail.company.com [198.51.100.10])
\tby mx.targetcorp.com with ESMTPS id 4h7kLm9Pq2z
\tfor <jane@targetcorp.com>; Thu, 24 Sep 2026 10:15:30 +0000
Authentication-Results: mx.targetcorp.com;
\tspf=pass smtp.mailfrom=sjenkins@company.com;
\tdkim=pass header.d=company.com;
\tdmarc=pass header.from=company.com
From: "Sarah Jenkins" <sjenkins@company.com>
To: Jane Doe <jane@targetcorp.com>
Subject: Q3 Financial Planning Notes & Project Roadmap
Date: Thu, 24 Sep 2026 10:14:50 +0000
Message-ID: <msg-20260924-001@company.com>

Hi Jane, please find attached the revised project roadmap for our sync this afternoon.`,

        bec: `Received: from mail-east.enterprise-corp.com (mail-east.enterprise-corp.com [198.51.100.44])
\tby mx.targetcorp.com with ESMTPS id 8R4jKm2Zq1z01
\tfor <cfo@targetcorp.com>; Thu, 24 Sep 2026 12:30:00 +0000
Authentication-Results: mx.targetcorp.com;
\tspf=pass smtp.mailfrom=john.doe@enterprise-corp.com;
\tdkim=pass header.d=enterprise-corp.com;
\tdmarc=pass header.from=enterprise-corp.com
From: "John Doe - CEO" <john.doe@enterprise-corp.com>
To: CFO <cfo@targetcorp.com>
Reply-To: "John Doe" <john.doe.enterprise2026@gmail.com>
Subject: URGENT: Confidential Acquisition Wire Confirmation Required Today
Date: Thu, 24 Sep 2026 12:29:10 +0000
Message-ID: <ceo-urgent-msg-9921@enterprise-corp.com>

Please process the wire transfer according to the confidential schedule immediately and reply to this email.`,

        tor: `Received: from tor-relay-exit5.onionmail.org (tor-relay-exit5.onionmail.org [185.220.101.5])
\tby mx.targetcorp.com with ESMTP id 9X2mPo4Lq
\tfor <security@targetcorp.com>; Thu, 24 Sep 2026 16:45:00 +0000
From: "Security Ops" <whistleblower@onionmail.org>
To: security@targetcorp.com
Subject: Notice: Operational Update Regarding Infrastructure
Date: Thu, 24 Sep 2026 16:44:00 +0000
Message-ID: <tor-msg-20260924-881@onionmail.org>

Please review internal operational procedures regarding secure node relaying.`,

        lookalike: `Received: from mail.paypa1-security-verification.com (mail.paypa1-security-verification.com [198.51.100.88])
\tby mx.targetcorp.com with ESMTPS id 6P9kLm1Qq
\tfor <user@targetcorp.com>; Thu, 24 Sep 2026 09:20:00 +0000
Authentication-Results: mx.targetcorp.com;
\tspf=softfail smtp.mailfrom=support@paypa1-security-verification.com;
\tdmarc=fail
From: "PayPal Security Center" <support@paypa1-security-verification.com>
To: user@targetcorp.com
Subject: Account Verification Required - Unauthorized Transaction Blocked
Date: Thu, 24 Sep 2026 09:19:00 +0000
Message-ID: <pay-alert-4491@paypa1-security-verification.com>

Your PayPal balance was placed on hold. Please update your identity immediately at https://paypa1-security-verification.com/login`,

        phish: `Received: from mail.cloud-verify-login.xyz (mail.cloud-verify-login.xyz [198.51.100.77])
\tby mx.targetcorp.com with ESMTP id 3N5kLm8Rq
\tfor <admin@targetcorp.com>; Thu, 24 Sep 2026 08:00:00 +0000
From: "security@microsoft.com" <admin@cloud-verify-login.xyz>
To: admin@targetcorp.com
Subject: ACTION REQUIRED: Password Expires in 2 Hours
Date: Thu, 24 Sep 2026 07:59:00 +0000
Message-ID: <pwd-expiry-99212@cloud-verify-login.xyz>

Your Microsoft 365 password expires today. Keep your current password by verifying here: https://cloud-verify-login.xyz/auth`
    };

    function bindForensicPresets() {
        const presets = [
            { id: 'btn-forensic-preset-legit', key: 'legit' },
            { id: 'btn-forensic-preset-bec', key: 'bec' },
            { id: 'btn-forensic-preset-tor', key: 'tor' },
            { id: 'btn-forensic-preset-lookalike', key: 'lookalike' },
            { id: 'btn-forensic-preset-phish', key: 'phish' }
        ];

        presets.forEach(p => {
            const btn = document.getElementById(p.id);
            if (btn) {
                btn.addEventListener('click', () => {
                    const textEl = document.getElementById('forensic-raw-text');
                    if (textEl) {
                        textEl.value = EML_PRESETS[p.key];
                        // Auto-run analysis for fast demonstration
                        runForensicAnalysis();
                    }
                });
            }
        });

        const clearBtn = document.getElementById('btn-clear-forensics');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                document.getElementById('forensic-raw-text').value = '';
                document.getElementById('forensic-file-input').value = '';
                document.getElementById('forensic-results-container').style.display = 'none';
                lastForensicResult = null;
            });
        }

        const runBtn = document.getElementById('btn-run-forensics');
        if (runBtn) {
            runBtn.addEventListener('click', runForensicAnalysis);
        }

        const fileInput = document.getElementById('forensic-file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                if (e.target.files && e.target.files[0]) {
                    const reader = new FileReader();
                    reader.onload = (evt) => {
                        document.getElementById('forensic-raw-text').value = evt.target.result;
                    };
                    reader.readAsText(e.target.files[0]);
                }
            });
        }
    }

    async function runForensicAnalysis() {
        const rawText = document.getElementById('forensic-raw-text').value.trim();
        const fileInput = document.getElementById('forensic-file-input');
        const loading = document.getElementById('forensic-loading');
        const resultsBox = document.getElementById('forensic-results-container');

        if (!rawText && (!fileInput.files || !fileInput.files[0])) {
            alert('Please select an .eml file or paste raw email source.');
            return;
        }

        loading.style.display = 'block';
        resultsBox.style.display = 'none';

        try {
            let resp;
            if (fileInput.files && fileInput.files[0]) {
                const formData = new FormData();
                formData.append('file', fileInput.files[0]);
                resp = await fetch(`${API_BASE}/api/forensics/analyze`, {
                    method: 'POST',
                    headers: { 'X-API-Key': FORENSIC_API_KEY },
                    body: formData
                });
            } else {
                lastForensicRawText = rawText;
                resp = await fetch(`${API_BASE}/api/forensics/analyze`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': FORENSIC_API_KEY
                    },
                    body: JSON.stringify({ raw_content: rawText })
                });
            }

            if (!resp.ok) {
                throw new Error(`Server returned status ${resp.status}`);
            }

            const data = await resp.json();
            lastForensicResult = data;
            renderForensicResults(data);
        } catch (err) {
            alert(`Forensic analysis failed: ${err.message}. Ensure backend is running at ${API_BASE}.`);
        } finally {
            loading.style.display = 'none';
        }
    }

    function renderForensicResults(data) {
        const resultsBox = document.getElementById('forensic-results-container');
        resultsBox.style.display = 'block';

        const fs = data.fraud_score || {};
        const score = fs.overall_score || data.summary.risk_score || 0;
        const riskTier = fs.risk_tier || "LOW";
        const verdict = data.summary.verdict || "UNKNOWN";

        // 1. Verdict Banner
        const banner = document.getElementById('forensic-verdict-banner');
        banner.className = 'verdict-banner';
        if (riskTier === 'CRITICAL') banner.classList.add('verdict-critical_fraud');
        else if (riskTier === 'HIGH') banner.classList.add('verdict-phishing');
        else if (riskTier === 'MEDIUM') banner.classList.add('verdict-suspicious');
        else banner.classList.add('verdict-legitimate');

        document.getElementById('forensic-verdict-title').textContent = verdict;
        document.getElementById('forensic-verdict-desc').textContent = `Risk Tier: ${riskTier} | Category: ${fs.predicted_category || 'N/A'}`;
        document.getElementById('forensic-score-num').textContent = score;

        // 2. Probable Origin Infrastructure Status
        const ot = data.origin_trace;
        const originCard = document.getElementById('forensic-origin-status-card');
        if (originCard && ot) {
            originCard.style.display = 'block';
            const badge = document.getElementById('origin-status-badge');
            const confPill = document.getElementById('origin-confidence-pill');
            const msg = document.getElementById('origin-status-msg');
            const geoDet = document.getElementById('origin-geo-details');

            badge.textContent = ot.origin_status || 'PROVIDER_RELAY';
            if (ot.origin_status === 'ORIGIN_FOUND') {
                badge.style.background = '#dcfce7';
                badge.style.color = '#15803d';
            } else if (ot.origin_status === 'ANONYMIZED') {
                badge.style.background = '#fee2e2';
                badge.style.color = '#b91c1c';
            } else {
                badge.style.background = '#e0f2fe';
                badge.style.color = '#0369a1';
            }

            confPill.textContent = `Confidence: ${ot.confidence_level || 'Low'}`;
            msg.textContent = ot.status_message || '';

            if (ot.origin_status === 'ORIGIN_FOUND' && ot.geolocation) {
                const g = ot.geolocation;
                geoDet.textContent = `Probable origin infrastructure location: ${g.city || 'Unknown'}, ${g.region || ''} ${g.country || 'Unknown'} (Lat: ${g.latitude}, Lon: ${g.longitude}) | ISP: ${g.isp || 'N/A'}`;
            } else if (ot.origin_status === 'PROVIDER_RELAY') {
                geoDet.textContent = `Egress Provider Relay: ${ot.origin_ip || 'Concealed'} (${ot.provider_name || 'Cloud Provider'}) | Probable origin infrastructure location cannot be determined from headers (Sender real client IP concealed by provider).`;
            } else if (ot.origin_status === 'ANONYMIZED' && ot.geolocation) {
                const g = ot.geolocation;
                geoDet.textContent = `Anonymizer Exit Node: ${ot.origin_ip} | Reported Location: ${g.city || 'Unknown'}, ${g.country || 'Unknown'} (Probable origin infrastructure location marked unreliable - VPN/Proxy/Tor)`;
            }
        }

        // 3. Origin Attribution
        const attr = data.attribution;
        if (attr) {
            document.getElementById('forensic-attr-archetype').textContent = attr.archetype.replace(/_/g, ' ');
            document.getElementById('forensic-attr-confidence').textContent = `Confidence: ${Math.round(attr.confidence * 100)}%`;
            document.getElementById('forensic-attr-title').textContent = attr.title;
            document.getElementById('forensic-attr-explanation').textContent = attr.explanation;
            
            const evList = document.getElementById('forensic-attr-evidence');
            evList.innerHTML = '';
            (attr.evidence || []).forEach(ev => {
                const li = document.createElement('li');
                li.textContent = ev;
                evList.appendChild(li);
            });
        }

        // 3b. Alternative Infrastructure Evidence (Task 2)
        const infra = data.infrastructure_evidence;
        const infraCard = document.getElementById('forensic-infra-card');
        if (infraCard) {
            const hasInfraData = infra && (
                (infra.links && infra.links.length > 0) ||
                (infra.reply_to && infra.reply_to.is_mismatch) ||
                (infra.sender_whois && infra.sender_whois.available) ||
                infra.sender_mx
            );

            if (hasInfraData) {
                infraCard.style.display = 'block';
                const explEl = document.getElementById('forensic-infra-explanation');
                explEl.textContent = infra.confidence_note || 
                    "When origin IP is concealed by provider relays or anonymizers, alternative infrastructure points provide secondary threat telemetry (probable infrastructure location, not sender location).";

                // Links table
                const linksTbody = document.getElementById('forensic-infra-links-body');
                const linksContainer = document.getElementById('forensic-infra-links-container');
                linksTbody.innerHTML = '';
                if (infra.links && infra.links.length > 0) {
                    linksContainer.style.display = 'block';
                    infra.links.forEach(l => {
                        const tr = document.createElement('tr');
                        const flags = [];
                        if (l.is_suspicious_hosting) flags.push('<span style="color:#dc2626;font-weight:bold;">🚨 Suspicious VPS</span>');
                        if (l.is_shortener) flags.push('<span style="color:#d97706;font-weight:bold;">🔗 Shortener</span>');
                        if (l.is_raw_ip) flags.push('<span style="color:#ea580c;font-weight:bold;">🔢 Raw IP</span>');
                        if (l.is_idn_homoglyph) flags.push('<span style="color:#b91c1c;font-weight:bold;">⚠️ Homoglyph</span>');
                        if (l.has_at_symbol) flags.push('<span style="color:#dc2626;font-weight:bold;">@ Delimiter</span>');
                        const flagsHtml = flags.length > 0 ? flags.join('<br>') : '<span style="color:#16a34a;">Standard</span>';
                        const loc = `${l.city ? l.city + ', ' : ''}${l.country || 'Unknown'}`;

                        tr.innerHTML = `
                            <td><strong>${l.domain}</strong><br><small style="color:#64748b;word-break:break-all;">${l.url}</small></td>
                            <td><code>${l.resolved_ip || 'Unresolved'}</code></td>
                            <td>${l.hosting_provider || '-'}<br><small style="color:#64748b;">ASN: ${l.asn || '-'}</small></td>
                            <td>${loc}</td>
                            <td>${flagsHtml}</td>
                        `;
                        linksTbody.appendChild(tr);
                    });
                } else {
                    linksContainer.style.display = 'none';
                }

                // Metadata (Reply-To & WHOIS & MX)
                const metaEl = document.getElementById('forensic-infra-meta-details');
                let metaHtml = '';
                if (infra.reply_to && infra.reply_to.is_mismatch) {
                    metaHtml += `<div style="margin-bottom:6px;padding:6px 10px;background:#fef2f2;border-radius:6px;border:1px solid #fecaca;color:#991b1b;">
                        ⚠️ <strong>Reply-To Mismatch:</strong> Inbound responses will be directed to <code>${infra.reply_to.reply_to_address}</code> (Domain: <strong>${infra.reply_to.reply_to_domain}</strong>, Resolved: <code>${infra.reply_to.resolved_ip || 'N/A'}</code>, Hosting: ${infra.reply_to.hosting_provider || 'N/A'}).
                    </div>`;
                }
                if (infra.sender_whois && infra.sender_whois.available) {
                    const w = infra.sender_whois;
                    const youngBadge = w.is_newly_registered ? ' <span style="color:#dc2626;font-weight:bold;">[NEWLY REGISTERED &lt;30 DAYS]</span>' : '';
                    metaHtml += `<div style="margin-bottom:6px;padding:6px 10px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;">
                        🌐 <strong>Domain Registration Telemetry:</strong> Created: <strong>${w.creation_date || 'N/A'}</strong> (${w.domain_age_days !== null ? w.domain_age_days + ' days old' : 'Age Unknown'})${youngBadge} | Registrar: ${w.registrar || 'N/A'} | Country: ${w.country || 'N/A'}
                    </div>`;
                }
                if (infra.sender_mx && infra.sender_mx.mx_host) {
                    const mx = infra.sender_mx;
                    metaHtml += `<div style="padding:6px 10px;background:#f8fafc;border-radius:6px;border:1px solid #e2e8f0;">
                        📬 <strong>Mail Exchange (MX) Infrastructure:</strong> <code>${mx.mx_host}</code> (Resolved: <code>${mx.resolved_ip || 'N/A'}</code> | Hosting: ${mx.hosting_provider || 'N/A'} | ASN: ${mx.asn || 'N/A'})
                    </div>`;
                }
                metaEl.innerHTML = metaHtml;
            } else {
                infraCard.style.display = 'none';
            }
        }

        // 4. 5-Factor Score Matrix
        const factorsGrid = document.getElementById('forensic-factors-grid');
        factorsGrid.innerHTML = '';
        if (fs.nlp_linguistic_factor) {
            const factors = [
                fs.nlp_linguistic_factor,
                fs.header_transport_factor,
                fs.authentication_factor,
                fs.domain_intel_factor,
                fs.ip_reputation_factor
            ];
            factors.forEach(f => {
                const pct = Math.min(100, (f.score / f.max_score) * 100);
                const pillClass = f.status === 'CRITICAL' ? 'pill-critical' : (f.status === 'WARNING' ? 'pill-warning' : 'pill-clean');
                const card = document.createElement('div');
                card.className = 'factor-card';
                card.innerHTML = `
                    <div class="factor-title">${f.factor_name}</div>
                    <div class="factor-score-val">${f.score} / ${f.max_score}</div>
                    <div class="factor-progress-bg">
                        <div class="factor-progress-bar" style="width: ${pct}%; background: ${f.status === 'CRITICAL' ? '#dc2626' : (f.status === 'WARNING' ? '#f59e0b' : '#10b981')}"></div>
                    </div>
                    <span class="factor-status-pill ${pillClass}">${f.status}</span>
                `;
                factorsGrid.appendChild(card);
            });
        }

        // 5. Interactive SVG Threat Graph
        renderThreatGraphSVG(data);

        // 6. Hop-by-Hop Trace Table
        const hopsBody = document.getElementById('forensic-hops-body');
        hopsBody.innerHTML = '';
        if (data.relay_path && data.relay_path.length > 0) {
            data.relay_path.forEach(h => {
                const tr = document.createElement('tr');
                const isInversion = (h.delay_flag === 'TIME_INVERSION') || (h.delay_seconds !== null && h.delay_seconds < -60);
                const isSkew = (h.delay_flag === 'CLOCK_SKEW') || (h.delay_seconds !== null && h.delay_seconds < 0 && h.delay_seconds >= -60);
                const isExtreme = (h.delay_flag === 'EXTREME_DELAY') || (h.delay_seconds !== null && h.delay_seconds > 86400);
                let delayText = h.delay_seconds !== null ? `${h.delay_seconds.toFixed(1)}s` : '-';
                if (isInversion) {
                    delayText = `⚠️ ${delayText} (Time Inversion)`;
                } else if (isSkew) {
                    delayText = `⚠️ ${delayText} (Clock Skew)`;
                } else if (isExtreme) {
                    delayText = `⚠️ ${(h.delay_seconds / 3600).toFixed(1)}h (Extreme Delay)`;
                }

                // Determine role badge
                let roleClass = 'role-relay';
                let roleLabel = h.hop_role || 'INTERMEDIATE_RELAY';
                if (roleLabel === 'PROBABLE_ORIGIN_INFRASTRUCTURE') roleClass = 'role-origin';
                else if (roleLabel === 'INBOUND_GATEWAY') roleClass = 'role-gateway';
                else if (roleLabel === 'INTERNAL_CLIENT_SUBMISSION') roleClass = 'role-client';

                // Format Geo / ASN / Provider
                let geoParts = [];
                if (h.city || h.country) {
                    geoParts.push(`${h.city ? h.city + ', ' : ''}${h.country || ''}`);
                }
                if (h.asn) {
                    geoParts.push(`ASN: ${h.asn}`);
                }
                let geoDisplay = geoParts.length > 0 ? geoParts.join('<br>') : (h.is_private_ip ? 'Private LAN' : '-');
                if (h.is_provider_relay && h.provider_name) {
                    geoDisplay += `<br><span class="provider-badge">${h.provider_name} Relay</span>`;
                }

                tr.innerHTML = `
                    <td><strong>Hop #${h.hop_number}</strong></td>
                    <td><span class="hop-role-badge ${roleClass}">${roleLabel.replace(/_/g, ' ')}</span></td>
                    <td><code>${h.from_host || '-'}</code></td>
                    <td><code>${h.from_ip || '-'}${h.is_private_ip ? ' (RFC1918)' : ''}</code></td>
                    <td style="font-size: 11px;">${geoDisplay}</td>
                    <td style="${isInversion || isExtreme ? 'color: #dc2626; font-weight: bold;' : (isSkew ? 'color: #d97706; font-weight: bold;' : '')}">${delayText}</td>
                    <td><code>${h.by_host || '-'}</code></td>
                `;
                hopsBody.appendChild(tr);
            });
        } else {
            hopsBody.innerHTML = '<tr><td colspan="7">No Received transmission hops present.</td></tr>';
        }

        // Bind Export Actions
        const pdfBtn = document.getElementById('btn-export-pdf');
        if (pdfBtn) {
            pdfBtn.onclick = downloadForensicPdf;
        }

        const siemBtn = document.getElementById('btn-export-siem');
        if (siemBtn) {
            siemBtn.onclick = downloadSiemJson;
        }

        resultsBox.scrollIntoView({ behavior: 'smooth' });
    }

    let activeGraphData = null;
    let activeGraphFilter = 'ALL';

    function initThreatGraphControls() {
        const filterBtns = document.querySelectorAll('.graph-filter-btn');
        filterBtns.forEach(btn => {
            btn.onclick = () => {
                filterBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeGraphFilter = btn.dataset.filter || 'ALL';
                if (activeGraphData) {
                    renderThreatGraphSVG(activeGraphData, activeGraphFilter);
                }
            };
        });
    }

    function renderThreatGraphSVG(data, filterMode = 'ALL') {
        activeGraphData = data;
        initThreatGraphControls();

        const container = document.getElementById('threat-graph-canvas');
        if (!container) return;

        let rawNodes = [];
        let rawEdges = [];

        if (data.threat_graph && data.threat_graph.nodes && data.threat_graph.nodes.length > 0) {
            rawNodes = JSON.parse(JSON.stringify(data.threat_graph.nodes));
            rawEdges = JSON.parse(JSON.stringify(data.threat_graph.edges || []));
        } else {
            // Synthesize graph from forensic data if threat_graph not present
            rawNodes.push({
                id: 'email:root',
                label: (data.envelope && data.envelope.subject) || 'Analyzed Email',
                type: 'email',
                risk: (data.summary && data.summary.risk_score >= 70) ? 'CRITICAL' : 'MEDIUM',
                score: (data.summary && data.summary.risk_score) || 50,
                details: { subject: data.envelope ? data.envelope.subject : '', verdict: data.summary ? data.summary.verdict : '' }
            });
            if (data.envelope && data.envelope.from_address) {
                rawNodes.push({
                    id: `sender:${data.envelope.from_address.toLowerCase()}`,
                    label: data.envelope.from_address,
                    type: 'sender',
                    risk: 'MEDIUM',
                    score: 40,
                    details: { address: data.envelope.from_address }
                });
                rawEdges.push({ source: 'email:root', target: `sender:${data.envelope.from_address.toLowerCase()}`, relationship: 'SENT_BY' });
            }
            if (data.relay_path) {
                let prevHopId = null;
                data.relay_path.forEach(h => {
                    const hId = `hop:${h.hop_number}`;
                    rawNodes.push({
                        id: hId,
                        label: `Hop #${h.hop_number}: ${h.from_ip || h.from_host || 'Relay'}`,
                        type: 'hop',
                        risk: h.delay_flag === 'TIME_INVERSION' ? 'CRITICAL' : 'MEDIUM',
                        score: h.delay_flag === 'TIME_INVERSION' ? 90 : 20,
                        details: h
                    });
                    if (prevHopId) {
                        rawEdges.push({ source: prevHopId, target: hId, relationship: h.delay_flag === 'TIME_INVERSION' ? 'INVERTED_RELAY_TO' : 'RELAYED_TO' });
                    }
                    prevHopId = hId;
                });
                if (data.relay_path.length > 0) {
                    rawEdges.push({ source: `hop:${data.relay_path[data.relay_path.length - 1].hop_number}`, target: 'email:root', relationship: 'INGRESS_TO' });
                }
            }
        }

        // Apply Entity Filtering
        let filteredNodes = rawNodes;
        if (filterMode === 'HOPS') {
            filteredNodes = rawNodes.filter(n => ['email', 'hop', 'ip', 'geo', 'asn', 'sender'].includes(n.type));
        } else if (filterMode === 'LINKS') {
            filteredNodes = rawNodes.filter(n => ['email', 'url', 'ip', 'asn', 'mx', 'domain'].includes(n.type));
        }
        const visibleIds = new Set(filteredNodes.map(n => n.id));
        const filteredEdges = rawEdges.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target));

        // Layout calculation across 740x380 viewport
        const width = 740;
        const height = 380;
        const emailNode = filteredNodes.find(n => n.type === 'email');
        if (emailNode) {
            emailNode.x = 370;
            emailNode.y = 190;
            emailNode.r = 20;
        }

        const senderNodes = filteredNodes.filter(n => n.type === 'sender');
        senderNodes.forEach((s, i) => {
            s.x = 110;
            s.y = 100 + (i * 90);
            s.r = 16;
        });

        const domainNodes = filteredNodes.filter(n => n.type === 'domain');
        domainNodes.forEach((d, i) => {
            d.x = 110;
            d.y = 230 + (i * 80);
            d.r = 15;
        });

        const hopNodes = filteredNodes.filter(n => n.type === 'hop');
        hopNodes.forEach((h, i) => {
            const total = Math.max(1, hopNodes.length);
            const startX = 220;
            const availWidth = 320;
            h.x = startX + (i * (availWidth / Math.max(1, total - 1 || 1)));
            h.y = 75 + (i % 2 === 0 ? 0 : 25);
            h.r = 16;
        });

        const urlNodes = filteredNodes.filter(n => n.type === 'url');
        urlNodes.forEach((u, i) => {
            u.x = 610;
            u.y = 90 + (i * 65);
            u.r = 15;
        });

        const netNodes = filteredNodes.filter(n => ['ip', 'geo', 'asn'].includes(n.type));
        netNodes.forEach((net, i) => {
            const total = Math.max(1, netNodes.length);
            net.x = 240 + (i * (300 / Math.max(1, total - 1 || 1)));
            net.y = 310 + (i % 2 === 0 ? 0 : 20);
            net.r = 14;
        });

        const mxNodes = filteredNodes.filter(n => n.type === 'mx');
        mxNodes.forEach((mx, i) => {
            mx.x = 120;
            mx.y = 330 + (i * 35);
            mx.r = 14;
        });

        const otherNodes = filteredNodes.filter(n => !['email', 'sender', 'domain', 'hop', 'url', 'ip', 'geo', 'asn', 'mx'].includes(n.type));
        otherNodes.forEach((o, i) => {
            o.x = 370 + (i * 60);
            o.y = 360;
            o.r = 15;
        });

        function getNodeColor(n) {
            switch(n.type) {
                case 'email': return '#3b82f6';
                case 'sender': return '#8b5cf6';
                case 'domain': return (n.details && n.details.lookalike) ? '#ef4444' : '#6366f1';
                case 'hop':
                    if (n.details && n.details.delay_flag === 'TIME_INVERSION') return '#ef4444';
                    if (n.details && n.details.delay_flag === 'CLOCK_SKEW') return '#f59e0b';
                    if (n.details && n.details.role === 'INBOUND_GATEWAY') return '#0284c7';
                    return '#06b6d4';
                case 'ip': return '#0ea5e9';
                case 'geo': return '#10b981';
                case 'asn': return '#64748b';
                case 'url': return (n.risk === 'CRITICAL' || (n.details && n.details.is_shortener)) ? '#ef4444' : '#f97316';
                case 'mx': return '#a855f7';
                case 'campaign': return '#f43f5e';
                default: return '#64748b';
            }
        }

        // Build SVG Output
        let svg = `<svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" style="user-select: none;">`;
        svg += `<defs>
            <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#000000" flood-opacity="0.6"/>
            </filter>
            <marker id="arrowhead-normal" markerWidth="7" markerHeight="5" refX="16" refY="2.5" orient="auto">
                <polygon points="0 0, 7 2.5, 0 5" fill="#475569"/>
            </marker>
            <marker id="arrowhead-inversion" markerWidth="8" markerHeight="6" refX="18" refY="3" orient="auto">
                <polygon points="0 0, 8 3, 0 6" fill="#ef4444"/>
            </marker>
        </defs>`;

        // Draw Edges
        filteredEdges.forEach(e => {
            const s = filteredNodes.find(n => n.id === e.source);
            const t = filteredNodes.find(n => n.id === e.target);
            if (s && t) {
                const isInversion = (e.relationship === 'INVERTED_RELAY_TO');
                const strokeColor = isInversion ? '#ef4444' : '#475569';
                const strokeWidth = isInversion ? 2.5 : 1.8;
                const dashArray = isInversion ? '6 3' : '4 2';
                const marker = isInversion ? 'url(#arrowhead-inversion)' : 'url(#arrowhead-normal)';

                svg += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke="${strokeColor}" stroke-width="${strokeWidth}" stroke-dasharray="${dashArray}" marker-end="${marker}"/>`;
                
                const midX = (s.x + t.x) / 2;
                const midY = (s.y + t.y) / 2;
                const relText = (e.relationship || '').replace(/_/g, ' ');
                svg += `<rect x="${midX - 35}" y="${midY - 8}" width="70" height="12" rx="3" fill="#0f172a" fill-opacity="0.8"/>`;
                svg += `<text x="${midX}" y="${midY + 1}" fill="${isInversion ? '#fca5a5' : '#94a3b8'}" font-size="8" font-weight="600" font-family="sans-serif" text-anchor="middle">${relText}</text>`;
            }
        });

        // Draw Nodes
        filteredNodes.forEach(n => {
            const color = getNodeColor(n);
            const truncated = n.label.length > 22 ? n.label.substring(0, 20) + '...' : n.label;
            svg += `
            <g class="graph-node-group" data-node-id="${n.id}" style="cursor: pointer;">
                <circle cx="${n.x}" cy="${n.y}" r="${n.r || 15}" fill="${color}" filter="url(#glow-effect)" stroke="#ffffff" stroke-width="1.8" class="graph-node-circle">
                    <title>${n.type.toUpperCase()}: ${n.label}</title>
                </circle>
                <text x="${n.x}" y="${n.y + (n.r || 15) + 13}" fill="#f1f5f9" font-size="9" font-weight="600" font-family="sans-serif" text-anchor="middle" style="pointer-events: none;">${truncated}</text>
            </g>`;
        });

        svg += `</svg>`;
        container.innerHTML = svg;

        // Wire Node Click & Hover Inspector
        const nodeGroups = container.querySelectorAll('.graph-node-group');
        nodeGroups.forEach(group => {
            const nodeId = group.dataset.nodeId;
            const nodeObj = filteredNodes.find(n => n.id === nodeId);
            if (nodeObj) {
                group.addEventListener('click', () => inspectGraphNode(nodeObj));
                group.addEventListener('mouseenter', () => {
                    const circle = group.querySelector('.graph-node-circle');
                    if (circle) circle.setAttribute('stroke', '#38bdf8');
                });
                group.addEventListener('mouseleave', () => {
                    const circle = group.querySelector('.graph-node-circle');
                    if (circle) circle.setAttribute('stroke', '#ffffff');
                });
            }
        });

        // Auto-inspect the highest risk node or email root by default
        const initialInspectNode = filteredNodes.find(n => n.risk === 'CRITICAL') || emailNode || filteredNodes[0];
        if (initialInspectNode) {
            inspectGraphNode(initialInspectNode);
        }
    }

    function inspectGraphNode(node) {
        const badge = document.getElementById('inspector-badge');
        const title = document.getElementById('inspector-title');
        const risk = document.getElementById('inspector-risk');
        const body = document.getElementById('inspector-body');
        if (!badge || !title || !risk || !body) return;

        badge.textContent = (node.type || 'ENTITY').toUpperCase();
        title.textContent = node.label || node.id;

        const riskVal = node.risk || 'LOW';
        risk.textContent = `${riskVal} RISK (Score: ${node.score || 0})`;
        if (riskVal === 'CRITICAL') {
            risk.style.background = '#fee2e2';
            risk.style.color = '#b91c1c';
        } else if (riskVal === 'HIGH') {
            risk.style.background = '#ffedd5';
            risk.style.color = '#c2410c';
        } else if (riskVal === 'MEDIUM') {
            risk.style.background = '#fef3c7';
            risk.style.color = '#b45309';
        } else {
            risk.style.background = '#dcfce7';
            risk.style.color = '#15803d';
        }

        const details = node.details || {};
        const entries = Object.entries(details).filter(([k, v]) => v !== null && v !== undefined && v !== '');

        if (entries.length === 0) {
            body.innerHTML = `<p style="margin: 0; color: #94a3b8; font-size: 11px;">Node ID: <code>${node.id}</code> (No additional forensic properties recorded).</p>`;
            return;
        }

        let gridHtml = `<div class="inspector-grid">`;
        entries.forEach(([key, val]) => {
            let displayVal = typeof val === 'object' ? JSON.stringify(val) : String(val);
            gridHtml += `
                <div class="inspector-item">
                    <div class="inspector-item-label">${key.replace(/_/g, ' ')}</div>
                    <div class="inspector-item-val">${displayVal}</div>
                </div>
            `;
        });
        gridHtml += `</div>`;
        body.innerHTML = gridHtml;
    }

    async function downloadForensicPdf() {
        if (!lastForensicRawText && !document.getElementById('forensic-raw-text').value) {
            alert('No active email source for PDF generation.');
            return;
        }
        const text = lastForensicRawText || document.getElementById('forensic-raw-text').value;

        try {
            const resp = await fetch(`${API_BASE}/api/reports/pdf/email`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-API-Key': FORENSIC_API_KEY
                },
                body: JSON.stringify({ raw_content: text })
            });

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `phishingguard_forensic_report_${Date.now()}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (err) {
            alert('Failed to download PDF report: ' + err.message);
        }
    }

    function downloadSiemJson() {
        if (!lastForensicResult) return;
        const blob = new Blob([JSON.stringify(lastForensicResult, null, 2)], { type: 'application/json' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `forensic_siem_bundle_${lastForensicResult.sha256.substring(0, 10)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    // =========================================================================
    // CASE MANAGEMENT & AUDIT CHAIN LOGIC
    // =========================================================================
    async function loadCasesAndCampaigns() {
        // 1. Load Cases
        try {
            const casesResp = await fetch(`${API_BASE}/api/cases`, {
                headers: { 'X-API-Key': FORENSIC_API_KEY }
            });
            if (casesResp.ok) {
                const cases = await casesResp.json();
                renderCasesTable(cases);
            }
        } catch (e) {
            console.error('Failed to load cases:', e);
        }

        // 2. Load Campaigns
        try {
            const campResp = await fetch(`${API_BASE}/api/campaigns`, {
                headers: { 'X-API-Key': FORENSIC_API_KEY }
            });
            if (campResp.ok) {
                const camps = await campResp.json();
                renderCampaigns(camps);
            }
        } catch (e) {
            console.error('Failed to load campaigns:', e);
        }

        // 3. Load Audit Chain & Verify
        loadAuditChain();
    }

    function renderCasesTable(cases) {
        const tbody = document.getElementById('cases-table-body');
        if (!tbody) return;
        tbody.innerHTML = '';

        if (!cases || cases.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7">No active investigation cases. Click "New Investigation Case" above to open one.</td></tr>';
            return;
        }

        cases.forEach(c => {
            const tr = document.createElement('tr');
            const sevColor = c.severity === 'CRITICAL' ? '#dc2626' : (c.severity === 'HIGH' ? '#ea580c' : '#2563eb');
            tr.innerHTML = `
                <td><code>${c.id}</code></td>
                <td><strong>${c.title}</strong></td>
                <td><span style="color: ${sevColor}; font-weight: bold;">${c.severity}</span></td>
                <td><span class="status-pill status-${c.status.toLowerCase()}">${c.status}</span></td>
                <td>${c.email_count} emails</td>
                <td style="font-size: 11.5px; color: #64748b;">${c.created_at.substring(0, 16)}</td>
                <td>
                    <button class="small-btn" onclick="window.downloadCasePdf('${c.id}')">📄 PDF</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    window.downloadCasePdf = async function(caseId) {
        try {
            const resp = await fetch(`${API_BASE}/api/reports/pdf/case/${caseId}`, {
                headers: { 'X-API-Key': FORENSIC_API_KEY }
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const blob = await resp.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `case_report_${caseId}.pdf`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        } catch (e) {
            alert('Download failed: ' + e.message);
        }
    };

    function renderCampaigns(camps) {
        const container = document.getElementById('campaigns-container');
        if (!container) return;
        container.innerHTML = '';

        if (!camps || camps.length === 0) {
            container.innerHTML = '<p style="color: var(--text-muted); font-size: 13px;">No coordinated multi-incident campaigns detected yet.</p>';
            return;
        }

        camps.forEach(camp => {
            const card = document.createElement('div');
            card.className = 'campaign-card';
            card.innerHTML = `
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 6px;">
                    <span class="campaign-badge">${camp.status}</span>
                    <span style="font-size: 11px; font-weight: 600; color: #dc2626;">${camp.incident_count} Linked Incidents</span>
                </div>
                <h4>${camp.name}</h4>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">
                    <strong>Actor Type:</strong> ${camp.threat_actor_type}
                </div>
                <div style="font-size: 11.5px; color: var(--text-muted); margin-bottom: 6px;">
                    <strong>Primary IOC:</strong> <code>${camp.primary_ioc || 'N/A'}</code>
                </div>
                <p style="font-size: 12px; margin: 0; line-height: 1.4;">${camp.summary || ''}</p>
            `;
            container.appendChild(card);
        });
    }

    async function loadAuditChain() {
        const ind = document.getElementById('chain-status-indicator');
        const verifyBanner = document.getElementById('chain-verify-result');
        const tbody = document.getElementById('audit-chain-body');

        try {
            // Check verification
            const vResp = await fetch(`${API_BASE}/api/audit/verify`, {
                headers: { 'X-API-Key': FORENSIC_API_KEY }
            });
            if (vResp.ok) {
                const vData = await vResp.json();
                if (vData.verified) {
                    ind.textContent = `🔐 Audit Chain: VALID (${vData.total_records} blocks)`;
                    ind.style.borderColor = '#10b981';
                    ind.style.color = '#065f46';
                    if (verifyBanner) {
                        verifyBanner.className = 'chain-verify-banner success';
                        verifyBanner.textContent = `✅ Cryptographic verification confirmed: ${vData.total_records} blocks chained with SHA-256 integrity.`;
                    }
                } else {
                    ind.textContent = '🚨 Audit Chain: TAMPERED';
                    ind.style.borderColor = '#ef4444';
                    ind.style.color = '#991b1b';
                    if (verifyBanner) {
                        verifyBanner.className = 'chain-verify-banner error';
                        verifyBanner.textContent = `⚠️ Hash Chain Mismatch detected at sequence #${vData.broken_at_sequence}!`;
                    }
                }
            }

            // Load records
            const cResp = await fetch(`${API_BASE}/api/audit/chain?limit=15`, {
                headers: { 'X-API-Key': FORENSIC_API_KEY }
            });
            if (cResp.ok && tbody) {
                const logs = await cResp.json();
                tbody.innerHTML = '';
                if (logs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6">No chain blocks recorded yet.</td></tr>';
                    return;
                }
                logs.forEach(l => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>#${l.sequence}</strong></td>
                        <td><span style="font-size: 11px; font-weight: 600; color: #2563eb;">${l.event_type}</span></td>
                        <td>${l.target_id ? l.target_id.substring(0, 20) + '...' : '-'}</td>
                        <td>${l.analyst_id || 'SYSTEM'}</td>
                        <td><code>${l.current_hash.substring(0, 16)}...</code></td>
                        <td style="font-size: 11px; color: #64748b;">${l.timestamp.substring(11, 19)}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        } catch (e) {
            console.error('Failed to load audit chain:', e);
        }
    }

    function bindCaseActions() {
        const openModalBtn = document.getElementById('btn-open-create-case-modal');
        const cancelBtn = document.getElementById('btn-cancel-case');
        const submitBtn = document.getElementById('btn-submit-case');
        const panel = document.getElementById('create-case-panel');
        const refreshBtn = document.getElementById('btn-refresh-cases');
        const verifyBtn = document.getElementById('btn-verify-chain');

        if (openModalBtn && panel) {
            openModalBtn.addEventListener('click', () => {
                panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
            });
        }
        if (cancelBtn && panel) {
            cancelBtn.addEventListener('click', () => panel.style.display = 'none');
        }
        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadCasesAndCampaigns);
        }
        if (verifyBtn) {
            verifyBtn.addEventListener('click', async () => {
                const verifyBanner = document.getElementById('chain-verify-result');
                if (verifyBanner) verifyBanner.style.display = 'block';
                await loadAuditChain();
            });
        }

        if (submitBtn) {
            submitBtn.addEventListener('click', async () => {
                const title = document.getElementById('new-case-title').value.trim();
                const severity = document.getElementById('new-case-severity').value;
                const desc = document.getElementById('new-case-desc').value.trim();

                if (!title) {
                    alert('Please enter a case title.');
                    return;
                }

                try {
                    const resp = await fetch(`${API_BASE}/api/cases`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-API-Key': FORENSIC_API_KEY
                        },
                        body: JSON.stringify({
                            title: title,
                            severity: severity,
                            description: desc
                        })
                    });

                    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                    document.getElementById('new-case-title').value = '';
                    document.getElementById('new-case-desc').value = '';
                    if (panel) panel.style.display = 'none';
                    loadCasesAndCampaigns();
                } catch (e) {
                    alert('Failed to create case: ' + e.message);
                }
            });
        }
    }

    // Initialize Forensics & Case Bindings
    bindForensicPresets();
    bindCaseActions();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initDashboard);
} else {
    initDashboard();
}
