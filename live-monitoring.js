// Polls persisted events. No synthetic/demo activity is generated.
const API_BASE = `${API_ORIGIN}/api`;
const eventList = document.getElementById("eventList");
const pauseBtn = document.getElementById("pauseBtn");
const resumeBtn = document.getElementById("resumeBtn");
const monitoringMessage = document.getElementById("monitoringMessage");
let paused = false;
let trendChart;
let distributionChart;

function renderEvents(events) {
    eventList.replaceChildren();
    if (!events.length) {
        const empty = document.createElement("p");
        empty.textContent = "No events have arrived yet. Create an integration key and send a test event.";
        eventList.appendChild(empty);
        return;
    }
    events.slice(0, 8).forEach(event => {
        const item = document.createElement("div");
        item.className = "event-item";
        const severity = document.createElement("span");
        severity.className = `severity ${String(event.risk_level).toLowerCase()}`;
        severity.textContent = `${event.risk_level} · ${event.risk_score}`;
        const details = document.createElement("div");
        const title = document.createElement("h4");
        title.textContent = `${event.source} · ${event.event_type}`;
        const description = document.createElement("p");
        description.textContent = event.event_data;
        details.append(title, description);
        const time = document.createElement("span");
        time.className = "event-ip";
        time.textContent = new Date(event.observed_at).toLocaleString();
        item.append(severity, details, time);
        eventList.appendChild(item);
    });
}

async function refreshMonitoring() {
    if (paused) return;
    try {
        const [eventsResponse, statsResponse] = await Promise.all([
            apiFetch(`${API_BASE}/events?per_page=8`),
            apiFetch(`${API_BASE}/stats`)
        ]);
        if (!eventsResponse.ok || !statsResponse.ok) throw new Error("API request failed");
        const eventsData = await eventsResponse.json();
        const statsData = await statsResponse.json();
        const stats = statsData.stats;
        renderEvents(eventsData.events || []);
        document.getElementById("totalEvents").textContent = stats.total_events;
        document.getElementById("totalThreats").textContent = stats.total;
        document.getElementById("criticalAlerts").textContent = stats.by_risk_level.CRITICAL || 0;
        distributionChart.data.datasets[0].data = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(level => stats.event_by_risk_level[level] || 0);
        distributionChart.update();
        trendChart.data.labels = stats.hourly.map(bucket => bucket.hour.slice(11) + ":00");
        trendChart.data.datasets[0].data = stats.hourly.map(bucket => bucket.count);
        trendChart.update();
        monitoringMessage.textContent = `Connected · ${stats.today_events} events today · refreshed ${new Date().toLocaleTimeString()}`;
    } catch (_error) {
        monitoringMessage.textContent = "API unavailable. Start the backend to view ingested events.";
    }
}

pauseBtn.addEventListener("click", () => {
    paused = true;
    monitoringMessage.textContent = "Refresh paused. Existing event records remain visible.";
});
resumeBtn.addEventListener("click", () => {
    paused = false;
    refreshMonitoring();
});

trendChart = new Chart(document.getElementById("threatTrendChart"), {
    type: "line",
    data: { labels: [], datasets: [{ label: "Events with threat indicators", data: [], borderColor: "#00d9ff", backgroundColor: "rgba(0,217,255,.12)", fill: true, tension: .4 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#dceaff" } } }, scales: { x: { ticks: { color: "#8497b5" } }, y: { beginAtZero: true, ticks: { color: "#8497b5", precision: 0 } } } }
});

distributionChart = new Chart(document.getElementById("threatDistributionChart"), {
    type: "doughnut",
    data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["#ff5252", "#ffad42", "#ffe16b", "#42f5a7"], borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: "bottom", labels: { color: "#dceaff", padding: 15 } } } }
});

refreshMonitoring();
setInterval(refreshMonitoring, 10000);
