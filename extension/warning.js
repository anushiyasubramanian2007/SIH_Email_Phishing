document.addEventListener('DOMContentLoaded', () => {
    // Read the blocked URL and reasons from the URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    const targetUrl = urlParams.get('url');
    const reasonsParam = urlParams.get('reasons');
    
    // Display the URL
    if (targetUrl) {
        document.getElementById('target-url').textContent = targetUrl;
    } else {
        document.getElementById('target-url').textContent = "Unknown URL";
    }

    // Display the reasons
    const reasonsList = document.getElementById('reasons-list');
    if (reasonsParam) {
        try {
            const reasons = JSON.parse(decodeURIComponent(reasonsParam));
            reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = reason;
                reasonsList.appendChild(li);
            });
        } catch (e) {
            const li = document.createElement('li');
            li.textContent = "Security indicators were detected by PhishingGuard.";
            reasonsList.appendChild(li);
        }
    } else {
        const li = document.createElement('li');
        li.textContent = "Unknown reason.";
        reasonsList.appendChild(li);
    }

    // Handle 'Go Back'
    document.getElementById('btn-return').addEventListener('click', () => {
        // Just go back in history to the email
        window.history.back();
        // Fallback if history.back() doesn't work well due to how we redirected
        setTimeout(() => {
            window.close(); // If opened in a new tab
        }, 500);
    });

    // Handle 'Proceed Anyway'
    document.getElementById('btn-proceed').addEventListener('click', () => {
        if (targetUrl && confirm("Are you absolutely sure? This website might steal your information.")) {
            // Unblock and navigate
            window.location.href = targetUrl;
        }
    });
});
