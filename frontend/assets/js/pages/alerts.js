// Security Alerts: filtered, paginated alert queue with the triage workflow.
(() => {
    const PER_PAGE = 20;
    const ACTIVE = ["Open", "Acknowledged", "In Progress"];
    // Main next step for each status: [label, target status, needs a note]
    const NEXT_STEP = {
        Open: ["Acknowledge", "Acknowledged"],
        Acknowledged: ["Start work", "In Progress"],
        "In Progress": ["Resolve", "Resolved"],
        Resolved: ["Reopen", "Open"],
        "False Positive": ["Reopen", "Open"],
    };
    const ACTION_LABELS = {
        created: "Alert created",
        status_changed: "Status changed",
        marked_read: "Marked read",
        marked_unread: "Marked unread",
        archived: "Archived",
        legacy_imported: "Imported",
    };

    const { el, badge, timeEl, emptyState, formatNumber, formatDateTime, titleCase, tone } = window.csUI;
    const $ = id => document.getElementById(id);
    const filters = { status: $("statusFilter"), level: $("levelFilter"), unread: $("unreadOnly") };
    let page = 1;
    let pages = 1;

    // ---------- filters (initial values may come from the URL, e.g. ?is_read=false) ----------

    const params = new URLSearchParams(window.location.search);
    if (params.get("status")) filters.status.value = params.get("status");
    if (params.get("risk_level")) filters.level.value = params.get("risk_level").toUpperCase();
    if (params.get("is_read") === "false") filters.unread.setAttribute("aria-pressed", "true");

    const unreadOnly = () => filters.unread.getAttribute("aria-pressed") === "true";
    const hasFilters = () => Boolean(filters.status.value || filters.level.value || unreadOnly());

    function query() {
        const q = new URLSearchParams({ page: String(page), per_page: String(PER_PAGE) });
        if (filters.status.value) q.set("status", filters.status.value);
        if (filters.level.value) q.set("risk_level", filters.level.value);
        if (unreadOnly()) q.set("is_read", "false");
        return q;
    }

    function applyFilters() {
        page = 1;
        load();
    }

    filters.status.addEventListener("change", applyFilters);
    filters.level.addEventListener("change", applyFilters);
    filters.unread.addEventListener("click", () => {
        filters.unread.setAttribute("aria-pressed", String(!unreadOnly()));
        applyFilters();
    });
    $("clearFilters").addEventListener("click", () => {
        filters.status.value = "";
        filters.level.value = "";
        filters.unread.setAttribute("aria-pressed", "false");
        applyFilters();
    });

    // ---------- actions ----------

    async function update(alert, changes, successMessage) {
        try {
            await apiJson(`/api/alerts/${alert.id}`, { method: "PATCH", body: changes });
            if (successMessage) csUI.toast(successMessage, { tone: "success" });
            if (window.csNotifyChanged) window.csNotifyChanged();
            await load();
        } catch (error) {
            csUI.toast(error.message, { tone: "error", timeout: 7000 });
        }
    }

    async function changeStatus(alert, status) {
        let note = "";
        if (status === "Resolved") {
            note = await csUI.prompt({
                title: `Resolve alert #${alert.id}`,
                message: "Briefly note what was done. This is kept in the alert's history.",
                label: "Resolution note", required: true, confirmLabel: "Resolve alert",
                placeholder: "e.g. Blocked the source IP at the firewall",
                suggestions: ["Blocked the source IP", "Patched the affected endpoint", "Confirmed harmless after review"],
            });
            if (note === null) return;
        } else if (status === "False Positive") {
            note = await csUI.prompt({
                title: `Mark alert #${alert.id} as a false positive`,
                message: "Explain why this is not a real threat, so others can trust the decision.",
                label: "Reason", required: true, confirmLabel: "Mark false positive",
                suggestions: ["Our own security scanner", "Expected test traffic", "Rule matched harmless text"],
            });
            if (note === null) return;
        } else if (status === "Open" && !ACTIVE.includes(alert.status)) {
            note = await csUI.prompt({
                title: `Reopen alert #${alert.id}`,
                message: "Why does this alert need another look?",
                label: "Reason", confirmLabel: "Reopen alert",
            });
            if (note === null) return;
        }
        await update(alert, { status, resolution_note: note }, `Alert #${alert.id} is now ${status}.`);
    }

    async function archive(alert) {
        const confirmed = await csUI.confirm({
            title: `Archive alert #${alert.id}?`,
            message: "It leaves the active queue. Its history is kept for auditing.",
            confirmLabel: "Archive", danger: true,
        });
        if (!confirmed) return;
        try {
            await apiJson(`/api/alerts/${alert.id}`, { method: "DELETE" });
            csUI.toast(`Alert #${alert.id} archived.`, { tone: "success" });
            if (window.csNotifyChanged) window.csNotifyChanged();
            await load();
        } catch (error) {
            csUI.toast(error.message, { tone: "error", timeout: 7000 });
        }
    }

    async function toggleHistory(alert, container, button) {
        if (!container.hidden) {
            container.hidden = true;
            button.textContent = "History";
            return;
        }
        container.hidden = false;
        button.textContent = "Hide history";
        container.replaceChildren(el("li", { text: "Loading history…" }));
        try {
            const { activity } = await apiJson(`/api/alerts/${alert.id}/activity`);
            container.replaceChildren(...(activity.length ? activity : [null]).map(entry => {
                if (!entry) return el("li", { text: "No activity recorded." });
                const details = entry.details || {};
                const change = details.from && details.to ? `: ${details.from} → ${details.to}` : "";
                const note = details.note ? ` — “${details.note}”` : "";
                return el("li", {}, timeEl(entry.created_at),
                    `${ACTION_LABELS[entry.action] || entry.action}${change} · ${entry.actor || "System"}${note}`);
            }));
        } catch (error) {
            container.replaceChildren(el("li", { class: "text-critical", text: error.message }));
        }
    }

    // ---------- rendering ----------

    function alertCard(alert) {
        const active = ACTIVE.includes(alert.status);
        const [nextLabel, nextStatus] = NEXT_STEP[alert.status];
        const history = el("ul", { class: "history", hidden: true });
        const historyBtn = el("button", { type: "button", class: "btn btn-ghost btn-sm", text: "History" });
        historyBtn.addEventListener("click", () => toggleHistory(alert, history, historyBtn));

        const actions = el("div", { class: "alert-actions" },
            el("button", { type: "button", class: "btn btn-primary btn-sm", text: nextLabel, onclick: () => changeStatus(alert, nextStatus) }),
            active && nextStatus !== "Resolved" && el("button", {
                type: "button", class: "btn btn-secondary btn-sm", text: "Resolve", onclick: () => changeStatus(alert, "Resolved"),
            }),
            active && el("button", {
                type: "button", class: "btn btn-secondary btn-sm", text: "False positive", onclick: () => changeStatus(alert, "False Positive"),
            }),
            el("button", {
                type: "button", class: "btn btn-ghost btn-sm", text: alert.is_read ? "Mark unread" : "Mark read",
                onclick: () => update(alert, { is_read: !alert.is_read }),
            }),
            historyBtn,
            el("span", { class: "spacer" }),
            el("button", { type: "button", class: "btn btn-danger-ghost btn-sm", text: "Archive", onclick: () => archive(alert) }));

        const threats = (alert.detected_threats || []).join(", ");
        return el("article", {
            class: `alert-card tone-${tone(alert.risk_level)}${active ? "" : " is-closed"}`,
            "aria-label": `Alert ${alert.id}: ${threats}`,
        },
        el("div", { class: "alert-head" },
            !alert.is_read && el("span", { class: "unread-dot", title: "Unread" }),
            badge(alert.risk_level, `${alert.risk_level} · ${alert.risk_score}`),
            el("h3", { text: threats }),
            el("span", { class: "status-pill", "data-status": alert.status, text: alert.status })),
        el("div", { class: "alert-meta" },
            el("span", { class: "mono", text: `#${alert.id}` }),
            el("span", { text: `Source: ${alert.source || "manual"}` }),
            el("span", { title: formatDateTime(alert.created_at) }, "Detected ", timeEl(alert.created_at))),
        el("details", { class: "alert-event disclosure" },
            el("summary", { text: "Event data" }),
            el("pre", { text: alert.event_data })),
        el("p", { class: "alert-text" }, el("strong", { text: "Recommended: " }), alert.recommendation),
        alert.resolution_note && el("div", { class: "callout" },
            el("span", {}, el("strong", { text: alert.status === "Open" ? "Reopen note: " : "Resolution note: " }), alert.resolution_note)),
        actions,
        history);
    }

    function render(alerts, total) {
        const container = $("alertsContainer");
        container.replaceChildren();
        $("clearFilters").hidden = !hasFilters();
        $("totalAlerts").textContent = formatNumber(total);
        if (!alerts.length) {
            container.append(hasFilters()
                ? emptyState({
                    icon: "🔍", title: "No alerts match these filters",
                    actions: [{ label: "Clear filters", onClick: () => $("clearFilters").click() }],
                })
                : emptyState({
                    icon: "✅", title: "No alerts — you're all clear",
                    text: "Alerts appear here when an analyzed or ingested event matches a detection rule.",
                    actions: [{ label: "Analyze a sample", href: "../app.html#/analyze?sample=sqli", primary: true }],
                }));
            return;
        }
        alerts.forEach(alert => container.append(alertCard(alert)));
    }

    let loading = false;
    async function load() {
        if (loading) return;
        loading = true;
        let reload = false;
        try {
            const [data, statsData] = await Promise.all([apiJson(`/api/alerts?${query()}`), apiJson("/api/stats")]);
            pages = Math.max(1, data.pagination.pages);
            if (page > pages) {
                // The last page emptied (e.g. after archiving); show the new last page.
                page = pages;
                reload = true;
                return;
            }
            $("pageLabel").textContent = `Page ${page} of ${pages}`;
            $("previousPage").disabled = page <= 1;
            $("nextPage").disabled = page >= pages;
            const stats = statsData.stats;
            $("openAlerts").textContent = formatNumber(stats.open);
            $("unreadAlerts").textContent = formatNumber(stats.unread);
            const posture = $("postureValue");
            posture.textContent = stats.posture === "CLEAR" ? "Clear" : titleCase(stats.posture);
            posture.className = `stat-value text-${stats.posture === "CLEAR" ? "low" : tone(stats.posture)}`;
            render(data.alerts, data.pagination.total);
        } catch (error) {
            $("alertsContainer").replaceChildren(emptyState({
                icon: "⚠️", title: "Could not load alerts", text: error.message,
                actions: [{ label: "Try again", onClick: load }],
            }));
        } finally {
            loading = false;
            if (reload) load();
        }
    }

    $("previousPage").addEventListener("click", () => { if (page > 1) { page -= 1; load(); } });
    $("nextPage").addEventListener("click", () => { if (page < pages) { page += 1; load(); } });
    $("refreshBtn").addEventListener("click", load);
    window.addEventListener("cs:data-changed", load);
    load();
})();
