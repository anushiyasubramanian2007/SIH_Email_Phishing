document.addEventListener('DOMContentLoaded', () => {
    const dashboardBtn = document.getElementById('btn-dashboard');
    const openScannerBtn = document.getElementById('btn-open-scanner');
    const backendStatus = document.getElementById('backend-status');

    // Check backend health
    fetch("http://127.0.0.1:8000/api/health")
        .then(res => {
            if (res.ok) {
                backendStatus.textContent = "Online";
                backendStatus.className = "status-ok";
            } else {
                throw new Error("Backend offline");
            }
        })
        .catch(err => {
            backendStatus.textContent = "Offline (Port 8000)";
            backendStatus.className = "status-danger";
        });

    // Open Dashboard
    if (dashboardBtn) {
        dashboardBtn.addEventListener('click', () => {
            const url = chrome.runtime.getURL("dashboard.html");
            chrome.tabs.create({ url: url });
        });
    }

    // Open Scanner section directly
    if (openScannerBtn) {
        openScannerBtn.addEventListener('click', () => {
            const url = chrome.runtime.getURL("dashboard.html?section=scanner");
            chrome.tabs.create({ url: url });
        });
    }
});
