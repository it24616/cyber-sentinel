
const API_URL = "http://127.0.0.1:5000/api/alerts";

async function loadAlerts() {
    const container = document.getElementById("alertsContainer");

    container.innerHTML = "<p>Loading alerts...</p>";

    try {
        const response = await fetch(API_URL);
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Could not load alerts.");
        }

        const alerts = data.alerts;

        document.getElementById("totalAlerts").textContent =
            alerts.length;

        document.getElementById("openAlerts").textContent =
            alerts.filter(a => a.status === "Open").length;

        document.getElementById("unreadAlerts").textContent =
            alerts.filter(a => !a.is_read).length;

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
                    <p><strong>Read:</strong>
                        ${alert.is_read ? "Yes" : "No"}
                    </p>

                    <div class="alert-actions">
                        <button onclick="markAsRead(${alert.id})">
                            Mark as Read
                        </button>

                        <button onclick="markAsResolved(${alert.id})">
                            Mark as Resolved
                        </button>

                        <button onclick="deleteAlert(${alert.id})">
                            Delete
                        </button>
                    </div>
                </div>
            `;
        }).join("");

    } catch (error) {
        container.innerHTML =
            `<p>Could not load alerts: ${escapeHTML(error.message)}</p>`;
    }
}

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
        const response = await fetch(`${API_URL}/${id}`, {
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

function markAsResolved(id) {
    updateAlert(id, { status: "Resolved" });
}

async function deleteAlert(id) {
    if (!confirm("Are you sure you want to delete this alert?")) {
        return;
    }

    try {
        const response = await fetch(`${API_URL}/${id}`, {
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
