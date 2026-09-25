// PhishingGuard Background Service Worker

console.log("PhishingGuard background service worker initialized.");

chrome.runtime.onInstalled.addListener(() => {
    console.log("PhishingGuard Extension Installed Successfully.");
});

const API_URL = "http://127.0.0.1:8000/api/analyze/email";
const URL_API_URL = "http://127.0.0.1:8000/api/analyze/url";

// Listen for messages from content scripts and popups
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    if (request.action === "analyze_email") {
        console.log("Background received email analysis request:", request.data);
        fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request.data)
        })
        .then(response => {
            if (!response.ok) throw new Error("HTTP status " + response.status);
            return response.json();
        })
        .then(data => {
            console.log("Backend responded successfully:", data);
            sendResponse({ success: true, data: data });
        })
        .catch(error => {
            console.error("Background fetch error:", error);
            sendResponse({ success: false, error: error.toString() });
        });
        
        return true; // Tells Chrome we will call sendResponse asynchronously
    }
    
    if (request.action === "analyze_url") {
        console.log("Background received URL analysis request.");
        fetch(URL_API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(request.data)
        })
        .then(response => {
            if (!response.ok) throw new Error("HTTP status " + response.status);
            return response.json();
        })
        .then(data => sendResponse({ success: true, data: data }))
        .catch(error => sendResponse({ success: false, error: error.toString() }));
        
        return true; // Async response
    }

    if (request.action === "open_dashboard") {
        const url = chrome.runtime.getURL("dashboard.html");
        chrome.tabs.create({ url: url });
        sendResponse({ success: true });
        return true;
    }
});
