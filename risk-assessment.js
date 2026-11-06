const assessmentForm = document.getElementById("assessmentForm");
const analyzeBtn = document.getElementById("analyzeBtn");
const eventData = document.getElementById("eventData");
const eventType = document.getElementById("eventType");
const statusMessage = document.getElementById("statusMessage");
const characterCount = document.getElementById("characterCount");
const resultPanel = document.getElementById("resultPanel");
const riskScore = document.getElementById("riskScore");
const riskLevel = document.getElementById("riskLevel");
const scoreTrack = document.getElementById("scoreTrack");
const scoreBar = document.getElementById("scoreBar");
const scoreCaption = document.getElementById("scoreCaption");
const resultRecord = document.getElementById("resultRecord");
const recommendation = document.getElementById("recommendation");
const findingsList = document.getElementById("findingsList");
const findingCount = document.getElementById("findingCount");
const noFindings = document.getElementById("noFindings");

const examples = {
    log: {
        type: "log",
        text: "Multiple failed login attempts detected for an administrator account."
    },
    request: {
        type: "request",
        text: "GET /.env HTTP/1.1 - repeated requests from an unknown source"
    },
    clean: {
        type: "general",
        text: "Scheduled maintenance completed successfully. No errors reported."
    }
};

eventData.addEventListener("input", () => {
    characterCount.textContent = `${eventData.value.length.toLocaleString()} / 10,000`;
});

document.querySelectorAll(".example-button").forEach(button => {
    button.addEventListener("click", () => {
        const example = examples[button.dataset.example];
        if (!example) return;
        eventData.value = example.text;
        eventType.value = example.type;
        eventData.dispatchEvent(new Event("input"));
        eventData.focus();
    });
});

assessmentForm.addEventListener("submit", async event => {
    event.preventDefault();
    const input = eventData.value.trim();

    if (!input) {
        showStatus("Enter security event data before analyzing.", "error");
        eventData.focus();
        return;
    }

    setLoading(true);
    resultPanel.hidden = true;
    showStatus("Analyzing event with the security rules engine…", "loading");

    try {
        const response = await apiFetch(`${API_ORIGIN}/api/assess-risk`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                event_data: input,
                event_type: eventType.value
            })
        });
        const data = await response.json();

        if (!response.ok || !data.success || !data.result) {
            throw new Error(data.error || "Risk assessment could not be completed.");
        }

        renderResult(data);
        resultPanel.hidden = false;
        showStatus(
            data.result.risk_score > 0
                ? "Assessment complete. A security alert was added to your alert queue."
                : "Assessment complete. No configured threat indicator matched.",
            "success"
        );
        resultPanel.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        showStatus(
            error.message || "Could not reach the security service. Check your connection and try again.",
            "error"
        );
    } finally {
        setLoading(false);
    }
});

function renderResult(data) {
    const result = data.result;
    const score = Math.max(0, Math.min(100, Number(result.risk_score) || 0));
    const level = String(result.risk_level || "LOW").toUpperCase();
    const findings = Array.isArray(result.findings) ? result.findings : [];

    riskScore.textContent = String(score);
    riskLevel.textContent = level;
    riskLevel.className = `risk-badge ${level.toLowerCase()}`;
    scoreBar.style.width = `${score}%`;
    scoreTrack.setAttribute("aria-valuenow", String(score));
    scoreTrack.setAttribute("aria-valuetext", `${score} out of 100, ${level.toLowerCase()} risk`);
    scoreTrack.className = `score-track ${level.toLowerCase()}`;
    scoreCaption.textContent = score > 0
        ? `${level[0]}${level.slice(1).toLowerCase()} risk · review the findings below`
        : "Low risk · no configured indicators matched";
    recommendation.textContent = result.recommendation || "Review the event and continue monitoring.";
    resultRecord.textContent = data.alert_id
        ? `Alert #${data.alert_id}`
        : `Event #${data.event_id} · no alert raised`;

    findingsList.replaceChildren();
    findingCount.textContent = `${findings.length} ${findings.length === 1 ? "finding" : "findings"}`;
    noFindings.hidden = findings.length > 0;

    findings.forEach(finding => findingsList.appendChild(createFindingCard(finding)));
}

function createFindingCard(finding) {
    const card = document.createElement("article");
    card.className = "finding-card";

    const header = document.createElement("div");
    header.className = "finding-card-header";
    const title = document.createElement("h4");
    title.textContent = finding.name || finding.rule_id || "Detection finding";
    const category = document.createElement("span");
    category.className = "finding-category";
    category.textContent = finding.category || "Security";
    header.append(title, category);
    card.appendChild(header);

    if (finding.description) {
        const description = document.createElement("p");
        description.className = "finding-description";
        description.textContent = finding.description;
        card.appendChild(description);
    }

    const metadata = document.createElement("div");
    metadata.className = "finding-metadata";
    [finding.rule_id, finding.mitre && `MITRE ${finding.mitre}`, finding.cwe && `CWE ${finding.cwe}`]
        .filter(Boolean)
        .forEach(value => {
            const tag = document.createElement("span");
            tag.textContent = value;
            metadata.appendChild(tag);
        });
    if (metadata.childElementCount) card.appendChild(metadata);

    (Array.isArray(finding.evidence) ? finding.evidence : []).forEach(item => {
        if (!item.match) return;
        const evidence = document.createElement("p");
        evidence.className = "finding-evidence";
        const label = document.createElement("span");
        label.textContent = "Matched evidence";
        const match = document.createElement("code");
        match.textContent = item.match;
        evidence.append(label, match);
        card.appendChild(evidence);
    });

    if (finding.remediation) {
        const remediation = document.createElement("p");
        remediation.className = "finding-remediation";
        const label = document.createElement("strong");
        label.textContent = "Suggested action: ";
        remediation.append(label, document.createTextNode(finding.remediation));
        card.appendChild(remediation);
    }

    return card;
}

function showStatus(message, state) {
    statusMessage.textContent = message;
    statusMessage.className = state;
}

function setLoading(loading) {
    analyzeBtn.disabled = loading;
    analyzeBtn.classList.toggle("is-loading", loading);
    analyzeBtn.querySelector(".button-label").textContent = loading
        ? "Analyzing event…"
        : "Analyze event";
    assessmentForm.setAttribute("aria-busy", String(loading));
}
