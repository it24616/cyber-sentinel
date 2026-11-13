// Dashboard: account-wide figures, charts, recent alerts and the activity feed.
(() => {
    const REFRESH_MS = 30000;
    const { el, badge, timeEl, emptyState, relativeTime, formatNumber, titleCase, tone, LEVELS } = window.csUI;
    const $ = id => document.getElementById(id);

    const threatChart = csCharts.line($("threatChart"), { label: "Detections" });
    const distributionChart = csCharts.severityDoughnut($("distributionChart"));

    function setText(id, text, toneName) {
        const node = $(id);
        node.textContent = text;
        node.className = node.className.replace(/\btext-\w+\b/g, "").trim();
        if (toneName) node.classList.add(`text-${toneName}`);
    }

    function renderStats(stats) {
        $("onboarding").hidden = stats.total_events > 0;

        setText("totalAlerts", formatNumber(stats.total));
        $("totalAlertsMeta").textContent = `${formatNumber(stats.today)} today · ${formatNumber(stats.total_events)} events recorded`;
        setText("openAlerts", formatNumber(stats.open), stats.open ? "high" : "low");
        $("openAlertsMeta").textContent = `${formatNumber(stats.unread)} unread · ${formatNumber(stats.by_risk_level.CRITICAL)} critical in total`;

        const posture = stats.posture;
        setText("systemRiskLevel", posture === "CLEAR" ? "Clear" : titleCase(posture), posture === "CLEAR" ? "low" : tone(posture));
        $("systemRiskDetail").textContent = posture === "CLEAR"
            ? "No open alerts"
            : `${stats.open_by_risk_level[posture]} open ${posture.toLowerCase()} · ${stats.open} open in total`;

        csCharts.setData(threatChart,
            stats.daily.map(bucket => new Date(`${bucket.day}T00:00:00Z`).toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" })),
            stats.daily.map(bucket => bucket.count));
        csCharts.setSeverity(distributionChart, LEVELS.map(level => stats.by_risk_level[level]));

        $("severityLegend").replaceChildren(...LEVELS.map(level => el("li", {},
            el("span", { class: `dot dot-${tone(level)}` }),
            titleCase(level),
            el("strong", { text: formatNumber(stats.by_risk_level[level]) }))));
    }

    function renderMonitoring(ready, stats) {
        if (!ready) {
            setText("monitoringState", "Offline", "critical");
            $("monitoringDetail").textContent = "API or database unavailable";
            return;
        }
        setText("monitoringState", "Active", "low");
        $("monitoringDetail").textContent = stats.last_event_at
            ? `Last event ${relativeTime(stats.last_event_at)}`
            : "Waiting for the first event";
    }

    function renderAlerts(alerts) {
        const body = $("recentAlertsBody");
        body.replaceChildren();
        if (!alerts.length) {
            const cell = el("td", { colspan: "5" }, emptyState({
                icon: "✅", title: "No alerts yet",
                text: "Alerts appear here when an event matches a detection rule.",
            }));
            body.append(el("tr", {}, cell));
            return;
        }
        alerts.forEach(alert => {
            const threats = (alert.detected_threats || []).join(", ");
            body.append(el("tr", {},
                el("td", { class: "mono", text: `#${alert.id}` }),
                el("td", { class: "threat-cell", title: threats, text: threats }),
                el("td", {}, badge(alert.risk_level)),
                el("td", { text: alert.status }),
                el("td", { class: "nowrap" }, timeEl(alert.created_at))));
        });
    }

    function describeActivity(item) {
        const threat = (item.detected_threats || [])[0] || "Alert";
        const who = item.actor ? ` · by ${item.actor}` : "";
        const details = item.details || {};
        switch (item.action) {
            case "created":
                return [`${titleCase(item.risk_level)} alert #${item.alert_id} created`,
                    `${threat} · source ${details.source || item.source} · score ${details.risk_score ?? "—"}`];
            case "status_changed":
                return [`Alert #${item.alert_id}: ${details.from} → ${details.to}`,
                    (details.note ? `“${details.note}”` : threat) + who];
            case "marked_read": return [`Alert #${item.alert_id} marked read`, threat + who];
            case "marked_unread": return [`Alert #${item.alert_id} marked unread`, threat + who];
            case "archived": return [`Alert #${item.alert_id} archived`, threat + who];
            case "legacy_imported": return [`Alert #${item.alert_id} imported`, "Claimed from the pre-account database"];
            default: return [`Alert #${item.alert_id}: ${item.action}`, threat + who];
        }
    }

    function renderActivity(activity) {
        const list = $("activityList");
        list.replaceChildren();
        if (!activity.length) {
            list.append(el("li", {}, emptyState({
                icon: "🕘", title: "No activity yet",
                text: "Analyze an event or send one through an integration to get started.",
            })));
            return;
        }
        activity.forEach(item => {
            const [title, subtitle] = describeActivity(item);
            list.append(el("li", { class: "activity-item" },
                el("span", { class: `dot dot-${tone(item.risk_level)}` }),
                el("div", {}, el("h3", { text: title }), el("p", { text: subtitle })),
                timeEl(item.created_at)));
        });
    }

    async function apiReady() {
        try {
            const response = await fetch(`${API_ORIGIN}/api/health`, { credentials: "include" });
            return (await response.json()).status === "ready";
        } catch (_error) {
            return false;
        }
    }

    let loading = false;
    async function load() {
        if (loading) return;
        loading = true;
        const status = $("apiStatus");
        try {
            const [ready, statsData, alertsData, activityData] = await Promise.all([
                apiReady(),
                apiJson("/api/stats"),
                apiJson("/api/alerts?per_page=5"),
                apiJson("/api/activity?limit=8"),
            ]);
            renderStats(statsData.stats);
            renderMonitoring(ready, statsData.stats);
            renderAlerts(alertsData.alerts);
            renderActivity(activityData.activity);
            status.dataset.state = "live";
            status.textContent = `Updated ${new Date().toLocaleTimeString()}`;
        } catch (error) {
            renderMonitoring(false);
            status.dataset.state = "error";
            status.textContent = "API unavailable";
        } finally {
            loading = false;
        }
    }

    $("refreshBtn").addEventListener("click", load);
    window.addEventListener("cs:data-changed", load);
    setInterval(() => { if (!document.hidden) load(); }, REFRESH_MS);
    load();
})();
