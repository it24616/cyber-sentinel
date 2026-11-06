const analyzeBtn = document.getElementById("analyzeBtn");
const clearBtn = document.getElementById("clearBtn");

const eventInput = document.getElementById("eventInput");
const eventType = document.getElementById("eventType");

const resultPanel = document.getElementById("resultPanel");
const riskLevel = document.getElementById("riskLevel");
const threatType = document.getElementById("threatType");
const resultMessage = document.getElementById("resultMessage");
const recommendation = document.getElementById("recommendation");


analyzeBtn.addEventListener("click", function () {

    const input = eventInput.value.trim();

    if (input === "") {
        alert("Please enter security event data first.");
        return;
    }

    const text = input.toLowerCase();

    let risk = "LOW";
    let threat = "No Known Threat Pattern";
    let message = "No predefined threat pattern was detected in this input.";
    let action = "Continue monitoring and validate the event using trusted security logs.";

    // SQL Injection Detection
    const sqlPattern =
        /(\bunion\s+select\b|\bselect\b.+\bfrom\b|'\s*or\s+['"]?1['"]?\s*=\s*['"]?1|--\s*$|;\s*drop\s+table\b)/i;

    // Cross-Site Scripting Detection
    const xssPattern =
        /<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=|<\s*iframe\b/i;

    // Repeated Failed Login / Brute Force Indicators
    const bruteForcePattern =
        /(failed login|login failed|authentication failure|invalid password|multiple failed attempts|brute force)/i;

    if (sqlPattern.test(input)) {

        risk = "HIGH";
        threat = "Possible SQL Injection";

        message =
            "The input contains patterns commonly associated with SQL Injection attacks.";

        action =
            "Review the request and application logs. Use parameterized queries and input validation.";

    } else if (xssPattern.test(input)) {

        risk = "HIGH";
        threat = "Possible XSS Attack";

        message =
            "The input contains patterns commonly associated with Cross-Site Scripting.";

        action =
            "Apply output encoding, input validation, and a suitable Content Security Policy.";

    } else if (bruteForcePattern.test(input)) {

        risk = "HIGH";
        threat = "Possible Brute Force Activity";

        message =
            "The input contains failed-login indicators that may suggest repeated authentication attempts.";

        action =
            "Review authentication logs, apply rate limiting, and enable multi-factor authentication.";

    } else if (eventType.value === "url" && !/^https?:\/\//i.test(input)) {

        risk = "MEDIUM";
        threat = "Invalid URL Format";

        message =
            "The supplied text does not appear to be a complete HTTP or HTTPS URL.";

        action =
            "Verify the URL format before processing it.";

    }

    // Display Result
    resultPanel.hidden = false;

    riskLevel.textContent = risk;
    threatType.textContent = threat;
    resultMessage.textContent = message;
    recommendation.textContent = action;

    // Risk color
    riskLevel.className = "";

    if (risk === "HIGH") {
        riskLevel.classList.add("risk-high");
    } else if (risk === "MEDIUM") {
        riskLevel.classList.add("risk-medium");
    } else {
        riskLevel.classList.add("risk-low");
    }

    resultPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });

});


// Clear Button
clearBtn.addEventListener("click", function () {

    eventInput.value = "";
    eventType.value = "general";

    resultPanel.hidden = true;

});