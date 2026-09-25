// PhishingGuard Content Script
console.log("PhishingGuard content script active on Gmail!");

const analyzedMessages = new Set();

/**
 * Robustly extracts attachment filenames from Gmail DOM
 */
function extractAttachments(emailContainer) {
    const attachments = new Set();

    // Strategy 1: Standard Gmail attachment chips (.aZo, .aV3, .aQy)
    const nameElements = emailContainer.querySelectorAll('.aZo .aV3, span.aV3, div.aQy, span.aQy, .aQA, .aV4');
    nameElements.forEach(el => {
        const text = (el.innerText || el.textContent || '').trim();
        if (text && text.includes('.') && text.length < 120 && !text.includes('\n')) {
            attachments.add(text);
        }
    });

    // Strategy 2: download_url attribute used by Gmail preview cards
    const downloadUrlElements = emailContainer.querySelectorAll('[download_url]');
    downloadUrlElements.forEach(el => {
        const attr = el.getAttribute('download_url');
        if (attr) {
            const parts = attr.split(':');
            if (parts.length >= 2 && parts[1]) {
                try {
                    const filename = decodeURIComponent(parts[1]).trim();
                    if (filename && filename.includes('.')) attachments.add(filename);
                } catch (e) {}
            }
        }
    });

    // Strategy 3: Links with download attribute or attachment params
    const downloadLinks = emailContainer.querySelectorAll('a[download], a[href*="disp=attd"], a[href*="attid="]');
    downloadLinks.forEach(a => {
        const downloadAttr = (a.getAttribute('download') || '').trim();
        if (downloadAttr && downloadAttr.includes('.')) {
            attachments.add(downloadAttr);
        }
        const text = (a.innerText || a.textContent || '').trim();
        if (text && text.includes('.') && text.length < 80 && !text.includes('\n')) {
            attachments.add(text);
        }
    });

    // Strategy 4: Attachment aria-labels
    const ariaElements = emailContainer.querySelectorAll('[aria-label*="Attachment:"], [aria-label*="attachment:"]');
    ariaElements.forEach(el => {
        const label = el.getAttribute('aria-label') || '';
        const clean = label.replace(/attachment:\s*/i, '').trim();
        if (clean.includes('.')) attachments.add(clean);
    });

    return Array.from(attachments);
}

function extractEmailData(emailContainer) {
    const senderElement = emailContainer.querySelector('.gD');
    const senderEmail = senderElement ? senderElement.getAttribute('email') : 'Unknown';
    const senderName = senderElement ? senderElement.innerText : 'Unknown';

    const subjectElement = document.querySelector('h2.hP');
    const subject = subjectElement ? subjectElement.innerText : 'Unknown Subject';

    const bodyElement = emailContainer.querySelector('div.a3s');
    const bodyText = bodyElement ? bodyElement.innerText : '';

    const links = [];
    if (bodyElement) {
        const anchorTags = bodyElement.querySelectorAll('a');
        anchorTags.forEach(a => {
            if (a.href) links.push(a.href);
        });
    }

    // Extract attachments from container
    const attachments = extractAttachments(emailContainer);

    let isAuthenticated = true;
    const authWarning = emailContainer.querySelector('.rc');
    const viaTag = emailContainer.querySelector('.ajz');
    if (authWarning || (viaTag && viaTag.innerText.includes('via'))) {
        isAuthenticated = false;
    }

    return { 
        sender_name: senderName, 
        sender_email: senderEmail, 
        subject: subject, 
        body: bodyText, 
        links: links, 
        attachments: attachments,
        is_authenticated: isAuthenticated 
    };
}

function injectLoadingBanner(emailContainer) {
    if (emailContainer.querySelector('.phishingguard-banner')) return null;

    const banner = document.createElement('div');
    banner.className = 'phishingguard-banner phishingguard-banner-info';
    banner.id = 'pg-banner-' + Date.now(); 
    
    // Set explicit inline styles to protect against Gmail CSS overrides
    banner.style.cssText = `
        margin: 12px 0;
        padding: 14px 18px;
        border-radius: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 13px;
        line-height: 1.5;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        background-color: #eff6ff;
        border: 1px solid #bfdbfe;
        border-left: 6px solid #3b82f6;
        color: #1e3a8a;
        display: block;
        visibility: visible;
        z-index: 999;
    `;
    
    banner.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between;">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span style="font-size: 15px; font-weight: 700;">🛡️ PhishingGuard</span>
                <span style="background: #3b82f6; color: white; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase;">⏳ SCANNING...</span>
            </div>
        </div>
        <div style="margin-top: 6px; font-size: 13px; color: #1e40af;">
            Analyzing email text, sender integrity, URLs, and attachments...
        </div>
    `;

    const emailHeader = emailContainer.querySelector('.gE');
    if (emailHeader) {
        emailHeader.parentNode.insertBefore(banner, emailHeader.nextSibling);
    } else {
        emailContainer.prepend(banner);
    }
    
    return banner;
}

function updateBannerWithResult(banner, result) {
    banner.classList.remove('phishingguard-banner-info');
    
    const verdict = (result.verdict || 'safe').toLowerCase();
    const isPhishing = verdict === 'phishing';
    const isSuspicious = verdict === 'suspicious';
    const isLegitimate = verdict === 'legitimate' || verdict === 'safe';

    let bgColor = "#ecfdf5";
    let borderColor = "#10b981";
    let borderSub = "#a7f3d0";
    let textColor = "#064e3b";
    let badgeBg = "#10b981";
    let badgeText = "✅ LEGITIMATE (SAFE)";
    let titleText = "🛡️ PhishingGuard: LEGITIMATE";

    if (isPhishing) {
        bgColor = "#fef2f2";
        borderColor = "#ef4444";
        borderSub = "#fecaca";
        textColor = "#7f1d1d";
        badgeBg = "#ef4444";
        badgeText = "🚨 PHISHING DETECTED";
        titleText = "🚨 PhishingGuard: PHISHING (High Risk)";
    } else if (isSuspicious) {
        bgColor = "#fffbeb";
        borderColor = "#f59e0b";
        borderSub = "#fde68a";
        textColor = "#78350f";
        badgeBg = "#f59e0b";
        badgeText = "⚠️ SUSPICIOUS";
        titleText = "⚠️ PhishingGuard: SUSPICIOUS (Medium Risk)";
    }

    // Apply inline styles to guarantee high contrast and override Gmail styles
    banner.style.cssText = `
        margin: 12px 0;
        padding: 14px 18px;
        border-radius: 8px;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 13px;
        line-height: 1.5;
        box-shadow: 0 3px 10px rgba(0, 0, 0, 0.08);
        background-color: ${bgColor};
        border: 1px solid ${borderSub};
        border-left: 6px solid ${borderColor};
        color: ${textColor};
        display: block !important;
        visibility: visible !important;
        z-index: 999;
    `;

    // Indicators HTML
    let indicatorsHtml = "";
    if (result.indicators && result.indicators.length > 0) {
        indicatorsHtml = `<ul style="margin: 6px 0; padding-left: 20px; font-size: 12.5px;">` + 
            result.indicators.map(ind => `<li style="margin-bottom: 3px;">${ind.description}</li>`).join("") + 
            `</ul>`;
    }

    // Attachments breakdown HTML
    let attachmentsHtml = `<span style="color:#64748b;">📎 No attachments detected in email.</span>`;
    if (result.attachments_analyzed && result.attachments_analyzed.length > 0) {
        attachmentsHtml = result.attachments_analyzed.map(att => {
            let statusPill = `<span style="background:#d1fae5;color:#065f46;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;">✅ Clean Format</span>`;
            if (att.status === 'phishing') {
                statusPill = `<span style="background:#fee2e2;color:#991b1b;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;">🚨 DANGEROUS (${att.threat_type || 'Malware'})</span>`;
            } else if (att.status === 'suspicious') {
                statusPill = `<span style="background:#fef3c7;color:#92400e;padding:2px 7px;border-radius:4px;font-size:11px;font-weight:700;">⚠️ Risk (${att.threat_type || 'Macro'})</span>`;
            }
            return `
                <div style="display:flex;justify-content:space-between;align-items:center;padding:4px 0;border-bottom:1px dashed rgba(0,0,0,0.08);">
                    <span style="font-weight:600;">📎 ${att.filename}</span>
                    ${statusPill}
                </div>
            `;
        }).join("");
    }

    banner.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                <span style="font-size: 15px; font-weight: 800;">${titleText}</span>
                <span style="background: ${badgeBg}; color: white; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; text-transform: uppercase;">${badgeText}</span>
                <span style="font-size: 12px; opacity: 0.85;">(${result.risk_category || 'Low Risk'})</span>
            </div>
            <button class="pg-dismiss-btn" title="Dismiss Banner" style="background:transparent;border:none;font-size:16px;cursor:pointer;color:inherit;opacity:0.6;padding:2px 6px;">✕</button>
        </div>
        
        <div style="font-size: 13.5px; margin-bottom: 8px;">
            <strong>Analysis:</strong> ${result.explanation}
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 10px 0; background: rgba(255,255,255,0.65); padding: 10px; border-radius: 6px;">
            <div>
                <div style="font-size: 11.5px; font-weight: 700; text-transform: uppercase; color: #475569; margin-bottom: 4px;">📝 Text & AI NLP Analysis</div>
                <div style="font-size: 12.5px;">
                    ${isLegitimate ? '✅ AI NLP Model confirmed legitimate language patterns. No brand spoofing or threats found.' : 
                      isPhishing ? '🚨 AI NLP Engine or Heuristics detected deceptive phishing language or threats.' :
                      '⚠️ Urgency or promotional pressure flagged in text content.'}
                </div>
            </div>
            <div>
                <div style="font-size: 11.5px; font-weight: 700; text-transform: uppercase; color: #475569; margin-bottom: 4px;">📎 Attachment Security</div>
                <div style="font-size: 12.5px;">
                    ${attachmentsHtml}
                </div>
            </div>
        </div>

        ${indicatorsHtml ? `<div style="font-size:12px;font-weight:700;margin-top:6px;">Security Indicators:</div>${indicatorsHtml}` : ''}

        <div style="margin-top: 10px; padding: 8px 12px; background: rgba(255,255,255,0.8); border-radius: 6px; font-size: 12.5px; display: flex; justify-content: space-between; align-items: center;">
            <span><strong>Recommendation:</strong> ${result.recommended_action}</span>
            <a id="pg-open-dash" style="color:inherit;font-weight:700;text-decoration:underline;cursor:pointer;white-space:nowrap;margin-left:12px;">Open Dashboard →</a>
        </div>
    `;

    // Dismiss listener
    const dismissBtn = banner.querySelector('.pg-dismiss-btn');
    if (dismissBtn) {
        dismissBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            banner.style.display = 'none';
        });
    }

    // Dashboard link listener
    const dashLink = banner.querySelector('#pg-open-dash');
    if (dashLink) {
        dashLink.addEventListener('click', (e) => {
            e.stopPropagation();
            chrome.runtime.sendMessage({ action: "open_dashboard" });
        });
    }
}

function processEmails() {
    const emailContainers = document.querySelectorAll('div[data-message-id]');

    for (const container of emailContainers) {
        const messageId = container.getAttribute('data-message-id');
        const isExpanded = container.classList.contains('adx') === false;

        if (messageId && isExpanded && !analyzedMessages.has(messageId)) {
            analyzedMessages.add(messageId);
            
            const emailData = extractEmailData(container);
            const banner = injectLoadingBanner(container);
            
            if (banner) {
                console.log("Asking background script to analyze email:", emailData);
                
                chrome.runtime.sendMessage({ action: "analyze_email", data: emailData }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Extension communication error:", chrome.runtime.lastError);
                        banner.innerHTML = `<strong>⚠️ Warning:</strong> Extension communication error.`;
                        return;
                    }
                    
                    if (response && response.success) {
                        console.log("Received result from background:", response.data);
                        updateBannerWithResult(banner, response.data);
                    } else {
                        console.error("Backend error reported by background:", response ? response.error : "Unknown");
                        banner.innerHTML = `<strong>⚠️ Warning:</strong> Could not connect to PhishingGuard backend. Make sure the Python server is running on port 8000.`;
                        banner.style.backgroundColor = "#fff8e1";
                        banner.style.borderLeftColor = "#ffb300";
                    }
                });
            }
        }
    }
}

const observer = new MutationObserver((mutations) => {
    processEmails();
});

observer.observe(document.body, { childList: true, subtree: true });
processEmails();

// --- URL CLICK INTERCEPTION ---
document.addEventListener('click', (event) => {
    let target = event.target;
    while (target && target.tagName !== 'A') {
        target = target.parentNode;
    }

    if (target && target.tagName === 'A' && target.href) {
        const emailBody = target.closest('div.a3s');
        if (emailBody) {
            event.preventDefault();
            
            const url = target.href;
            console.log("PhishingGuard intercepted click to:", url);
            
            const originalText = target.innerText;
            target.innerText = "⏳ Checking link...";
            target.style.backgroundColor = "#ffeb3b";
            
            chrome.runtime.sendMessage({ action: "analyze_url", data: { url: url } }, (response) => {
                if (chrome.runtime.lastError) {
                    console.error("Extension communication error:", chrome.runtime.lastError);
                    window.location.href = url;
                    return;
                }
                
                if (response && response.success) {
                    const result = response.data;
                    if (result.verdict === "phishing" || result.verdict === "suspicious") {
                        const warningUrl = chrome.runtime.getURL("warning.html") + 
                                           "?url=" + encodeURIComponent(url) + 
                                           "&reasons=" + encodeURIComponent(JSON.stringify(result.indicators.map(i => i.description)));
                        window.location.href = warningUrl;
                    } else {
                        window.location.href = url;
                    }
                } else {
                    console.error("URL check failed", response ? response.error : "Unknown");
                    window.location.href = url;
                }
                
                target.innerText = originalText;
                target.style.backgroundColor = "transparent";
            });
        }
    }
});
