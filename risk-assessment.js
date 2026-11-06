
const analyzeBtn = document.getElementById("analyzeBtn");

const eventData = document.getElementById("eventData");
const statusMessage = document.getElementById("statusMessage");

const resultPanel = document.getElementById("resultPanel");

const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");

const threatList = document.getElementById("threatList");
const recommendation = document.getElementById("recommendation");


analyzeBtn.addEventListener("click", async function () {

    const input = eventData.value.trim();

    if (!input) {
        statusMessage.textContent =
            "Please enter security event data.";
        return;
    }

    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing...";

    statusMessage.textContent =
        "Connecting to Python Backend...";

    resultPanel.hidden = true;

    try {

        const response = await apiFetch(
            `${API_ORIGIN}/api/assess-risk`,
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    event_data: input
                })
            }
        );

        const data = await response.json();

        if (!response.ok || !data.success || !data.result) {
            throw new Error(
                data.error || "Risk assessment failed."
            );
        }

        const result = data.result;

        // Display Risk Score
        riskScore.textContent =
            result.risk_score + "/100";

        // Display Risk Level
        riskLevel.textContent =
            result.risk_level;

        riskLevel.className =
            result.risk_level.toLowerCase();

        // Display Detected Threats
        threatList.replaceChildren();

        result.detected_threats.forEach(function (threat) {

            const li = document.createElement("li");

            li.textContent = threat;

            threatList.appendChild(li);

        });

        // Display Recommendation
        recommendation.textContent =
            result.recommendation;

        // Show Result Panel
        resultPanel.hidden = false;

        // Show appropriate message
        if (result.risk_score > 0) {
            statusMessage.textContent =
                "Risk assessment completed. Security alert saved successfully.";
        } else {
            statusMessage.textContent =
                "Assessment completed. No known threat pattern detected.";
        }

        // Scroll to Result
        resultPanel.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    } catch (error) {

        statusMessage.textContent =
            "Error: " + error.message +
            " Please check Python Backend.";

    } finally {

        analyzeBtn.disabled = false;
        analyzeBtn.textContent = "Analyze Risk";

    }

});
