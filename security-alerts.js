
const API_URL = `${API_ORIGIN}/api/alerts`;
let alertPage = 1;
let alertPages = 1;

async function loadAlerts() {
    const container = document.getElementById("alertsContainer");

    container.innerHTML = "<p>Loading alerts...</p>";

    try {
        const query = new URLSearchParams({ page: String(alertPage), per_page: "20" });
        const status = document.getElementById("statusFilter")?.value;
        const level = document.getElementById("levelFilter")?.value;
        if (status) query.set("status", status);
        if (level) query.set("risk_level", level);
        const [response, statsResponse] = await Promise.all([apiFetch(`${API_URL}?${query}`), apiFetch("/api/stats")]);
        const data = await response.json();
        const statsData = await statsResponse.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not load alerts.");
        }

        if (!statsResponse.ok || !statsData.success) throw new Error(statsData.error || "Could not load alert counts.");
        const alerts = data.alerts;
        alertPages = Math.max(1, data.pagination.pages);
        document.getElementById("pageLabel").textContent = `Page ${alertPage} of ${alertPages}`;
        document.getElementById("previousPage").disabled = alertPage <= 1;
        document.getElementById("nextPage").disabled = alertPage >= alertPages;

        document.getElementById("totalAlerts").textContent =
            data.pagination.total;

        document.getElementById("openAlerts").textContent =
            statsData.stats.open;

        document.getElementById("unreadAlerts").textContent =
            statsData.stats.unread;

        if (alerts.length === 0) {
            container.innerHTML = "<p>No security alerts found.</p>";
            return;
        }

        container.innerHTML = alerts.map(alert => {
            const level = String(alert.risk_level).toLowerCase();

            const threats = alert.detected_threats
                .map(threat => escapeHTML(threat))
                .join(", ");

            return `
                <div class="alert-card ${level}">
                    <h3>${escapeHTML(alert.risk_level)} Risk Alert</h3>

                    <p><strong>Alert ID:</strong> ${alert.id}</p>
                    <p><strong>Source:</strong> ${escapeHTML(alert.source || "manual")}</p>
                    <p><strong>Risk Score:</strong> ${alert.risk_score}/100</p>
                    <p><strong>Detected Threats:</strong> ${threats}</p>
                    <p><strong>Event:</strong> ${escapeHTML(alert.event_data)}</p>
                    <p><strong>Recommendation:</strong>
                        ${escapeHTML(alert.recommendation)}
                    </p>
                    <p><strong>Date:</strong> ${escapeHTML(alert.created_at)}</p>
                    <p><strong>Status:</strong>
                        <span class="status">${escapeHTML(alert.status)}</span>
                    </p>
                    ${alert.resolution_note ? `<p><strong>Resolution note:</strong> ${escapeHTML(alert.resolution_note)}</p>` : ""}
                    <p><strong>Read:</strong>
                        ${alert.is_read ? "Yes" : "No"}
                    </p>

                    <div class="alert-actions">
                        <button onclick="markAsRead(${alert.id})">
                            Mark as Read
                        </button>

                        ${alert.status === "Open" ? `<button onclick="changeAlertStatus(${alert.id}, 'Acknowledged')">Acknowledge</button>` : ""}
                        ${alert.status === "Acknowledged" ? `<button onclick="changeAlertStatus(${alert.id}, 'In Progress')">Start Work</button>` : ""}
                        ${["Open", "Acknowledged", "In Progress"].includes(alert.status) ? `<button onclick="resolveAlert(${alert.id})">Resolve</button><button onclick="falsePositiveAlert(${alert.id})">False Positive</button>` : `<button onclick="reopenAlert(${alert.id})">Reopen</button>`}
                        <button onclick="showAlertActivity(${alert.id})">History</button>

                        <button onclick="deleteAlert(${alert.id})">
                            Archive
                        </button>
                    </div>
                    <div id="activity-${alert.id}" class="activity-history" hidden></div>
                </div>
            `;
        }).join("");

    } catch (error) {
        container.innerHTML =
            `<p>Could not load alerts: ${escapeHTML(error.message)}</p>`;
    }
}

document.getElementById("applyFilters").addEventListener("click", () => {
    alertPage = 1;
    loadAlerts();
});
document.getElementById("previousPage").addEventListener("click", () => {
    if (alertPage > 1) { alertPage--; loadAlerts(); }
});
document.getElementById("nextPage").addEventListener("click", () => {
    if (alertPage < alertPages) { alertPage++; loadAlerts(); }
});

function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

async function updateAlert(id, changes) {
    try {
        const response = await apiFetch(`${API_URL}/${id}`, {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(changes)
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Update failed.");
        }

        await loadAlerts();

    } catch (error) {
        alert(error.message);
    }
}

function markAsRead(id) {
    updateAlert(id, { is_read: true });
}

function changeAlertStatus(id, status, resolution_note = "") {
    updateAlert(id, { status, resolution_note });
}

function resolveAlert(id) {
    const note = prompt("Add a brief resolution note:");
    if (note === null) return;
    if (!note.trim()) {
        alert("A resolution note is required.");
        return;
    }
    changeAlertStatus(id, "Resolved", note.trim());
}

function falsePositiveAlert(id) {
    const note = prompt("Explain why this alert is a false positive:");
    if (note === null) return;
    if (!note.trim()) {
        alert("A reason is required.");
        return;
    }
    changeAlertStatus(id, "False Positive", note.trim());
}

function reopenAlert(id) {
    const note = prompt("Why is this alert being reopened?");
    if (note === null) return;
    changeAlertStatus(id, "Open", note.trim());
}

async function showAlertActivity(id) {
    const panel = document.getElementById(`activity-${id}`);
    panel.hidden = false;
    panel.textContent = "Loading history…";
    try {
        const response = await apiFetch(`${API_URL}/${id}/activity`);
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Could not load history.");
        panel.replaceChildren();
        if (!data.activity.length) {
            panel.textContent = "No activity recorded.";
            return;
        }
        data.activity.forEach(entry => {
            const line = document.createElement("p");
            const actor = entry.actor || "System";
            const details = entry.details || {};
            const transition = details.from && details.to ? `: ${details.from} → ${details.to}` : "";
            const note = details.note ? ` · ${details.note}` : "";
            line.textContent = `${new Date(entry.created_at).toLocaleString()} · ${actor} · ${entry.action}${transition}${note}`;
            panel.appendChild(line);
        });
    } catch (error) {
        panel.textContent = error.message;
    }
}

async function deleteAlert(id) {
    if (!confirm("Archive this alert from the active queue? Its audit history will be retained.")) {
        return;
    }

    try {
        const response = await apiFetch(`${API_URL}/${id}`, {
            method: "DELETE"
        });

        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Delete failed.");
        }

        await loadAlerts();

    } catch (error) {
        alert(error.message);
    }
}

loadAlerts();
