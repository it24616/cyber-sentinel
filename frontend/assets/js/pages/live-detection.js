// Live Detection: polls the detection overview for new events, plus hourly/severity charts.
(() => {
    const POLL_MS = 5000;
    const CHART_REFRESH_MS = 30000;
    const MAX_BACKOFF_MS = 60000;
    const FEED_LIMIT = 50;
    const PREFILL_KEY = "cs:analyze-prefill";

    const { el, badge, timeEl, emptyState, formatNumber, titleCase, tone, LEVELS } = window.csUI;
    const $ = id => document.getElementById(id);

    const state = {
        rules: new Map(),
        events: [],
        latestId: 0,
        paused: false,
        levelFilter: "",
        failures: 0,
        timer: null,
        inFlight: false,
        expanded: new Set(),
        loaded: false,
    };

    const trendChart = csCharts.line($("trendChart"), { label: "Detections" });
    const severityChart = csCharts.severityDoughnut($("severityChart"));

    const ruleName = id => state.rules.get(id)?.name || id.replace(/_/g, " ").toLowerCase();

    function setLiveStatus(kind, text) {
        $("liveStatus").dataset.state = kind;
        $("liveStatus").textContent = text;
    }

    // ---------- renderers ----------

    function renderKpis(overview) {
        const levels = overview.by_risk_level_24h;
        $("kpiEvents").textContent = formatNumber(overview.events_24h);
        $("kpiDetections").textContent = formatNumber(overview.detections_24h);
        const rate = overview.events_24h ? Math.round((overview.detections_24h / overview.events_24h) * 100) : 0;
        $("kpiRate").textContent = `Detection rate ${rate}%`;
        $("kpiSevere").textContent = `${formatNumber(levels.CRITICAL)} / ${formatNumber(levels.HIGH)}`;
        $("kpiMaxScore").textContent = `Peak score ${overview.max_score_24h}/100`;
        $("kpiEngine").textContent = `v${overview.engine.version}`;
        $("kpiRules").textContent = `${overview.engine.rule_count} rules · URL & HTML decoding`;
    }

    function renderBars(listId, items, labelFn, emptyText) {
        const list = $(listId);
        list.replaceChildren();
        if (!items.length) {
            list.append(el("li", { class: "empty-inline", text: emptyText }));
            return;
        }
        const max = Math.max(...items.map(item => item.count));
        items.forEach(item => {
            const fill = el("div", { class: "bar-fill" });
            fill.style.width = `${Math.max(4, (item.count / max) * 100)}%`;
            if (item.max_score !== undefined) {
                const level = item.max_score >= 80 ? "CRITICAL" : item.max_score >= 60 ? "HIGH" : item.max_score >= 30 ? "MEDIUM" : "LOW";
                fill.style.background = `var(--${tone(level)})`;
            }
            list.append(el("li", {},
                el("span", { class: "bar-name", title: labelFn(item), text: labelFn(item) }),
                el("span", { class: "bar-count", text: formatNumber(item.count) }),
                el("div", { class: "bar-track" }, fill)));
        });
    }

    function mergeEvents(incoming, isInitial) {
        if (!incoming.length) return;
        const known = new Set(state.events.map(event => event.id));
        const fresh = incoming.filter(event => !known.has(event.id));
        fresh.forEach(event => { event._new = !isInitial; });
        state.events = [...fresh, ...state.events].sort((a, b) => b.id - a.id).slice(0, FEED_LIMIT);
        if (!isInitial && fresh.length) {
            const severe = fresh.filter(event => ["CRITICAL", "HIGH"].includes(event.risk_level));
            if (severe.length) {
                csUI.toast(`${severe.length} new high-severity detection${severe.length > 1 ? "s" : ""}.`, { tone: "error" });
            }
            if (fresh.some(event => event.alert_id) && window.csNotifyChanged) window.csNotifyChanged();
        }
    }

    function analyzeAgain(event) {
        try {
            sessionStorage.setItem(PREFILL_KEY, JSON.stringify({ data: event.event_data, type: event.event_type }));
        } catch (_error) { /* storage blocked */ }
        if (window.csNavigate) window.csNavigate("#/analyze");
        else window.location.href = "analyze.html";
    }

    function feedItem(event) {
        const expanded = state.expanded.has(event.id);
        const title = event.matched_rules.length ? event.matched_rules.map(ruleName).join(", ") : "No indicator matched";
        const body = el("div", { class: "feed-body", hidden: !expanded },
            el("pre", { text: event.event_data }),
            el("div", { class: "feed-actions" },
                event.alert_id && el("a", {
                    class: "btn btn-secondary btn-sm", href: "../app.html#/alerts",
                    text: `Alert #${event.alert_id} · ${event.alert_status}`,
                }),
                el("button", { type: "button", class: "btn btn-ghost btn-sm", text: "Analyze again", onclick: () => analyzeAgain(event) })));
        const head = el("button", { type: "button", class: "feed-head", "aria-expanded": String(expanded) },
            badge(event.risk_level, `${event.risk_level} ${event.risk_score}`),
            el("span", { class: "feed-main" },
                el("strong", { text: title }),
                el("span", { text: `${event.source} · ${event.event_type}` })),
            timeEl(event.received_at));
        head.addEventListener("click", () => {
            const open = body.hidden;
            body.hidden = !open;
            head.setAttribute("aria-expanded", String(open));
            open ? state.expanded.add(event.id) : state.expanded.delete(event.id);
        });
        const item = el("li", { class: `feed-item tone-${tone(event.risk_level)}${event._new ? " is-new" : ""}` }, head, body);
        event._new = false;
        return item;
    }

    function renderFeed() {
        const feed = $("feed");
        feed.replaceChildren();
        const items = state.events.filter(event => !state.levelFilter || event.risk_level === state.levelFilter);
        if (!items.length) {
            feed.append(el("li", {}, state.events.length
                ? el("p", { class: "empty-inline", text: "No events at this severity." })
                : emptyState({
                    icon: "📡", title: "Waiting for events",
                    text: "Analyze an event or send one through an integration key. New events appear here within seconds.",
                    actions: [
                        { label: "Analyze a sample", href: "../app.html#/analyze?sample=sqli", primary: true },
                        { label: "Connect a source", href: "../app.html#/integrations" },
                    ],
                })));
            return;
        }
        items.forEach(event => feed.append(feedItem(event)));
    }

    async function loadCharts() {
        try {
            const { stats } = await apiJson("/api/stats");
            csCharts.setData(trendChart, stats.hourly.map(bucket => `${bucket.hour.slice(11)}:00`), stats.hourly.map(bucket => bucket.count));
            csCharts.setSeverity(severityChart, LEVELS.map(level => stats.event_by_risk_level[level]));
            $("severityLegend").replaceChildren(...LEVELS.map(level => el("li", {},
                el("span", { class: `dot dot-${tone(level)}` }), titleCase(level),
                el("strong", { text: formatNumber(stats.event_by_risk_level[level]) }))));
        } catch (_error) { /* charts keep their last data */ }
    }

    // ---------- polling ----------

    async function poll() {
        if (state.inFlight) return;
        state.inFlight = true;
        const isInitial = !state.loaded;
        try {
            const { overview } = await apiJson(`/api/detection/overview?limit=25&since_id=${state.latestId}`);
            state.failures = 0;
            renderKpis(overview);
            renderBars("topRules", overview.top_rules, item => ruleName(item.rule_id), "No indicators matched in the last 24 hours.");
            renderBars("topSources", overview.top_sources, item => item.source, "No sources with detections yet.");
            mergeEvents(overview.events, isInitial);
            state.latestId = Math.max(state.latestId, overview.latest_id);
            state.loaded = true;
            renderFeed();
            setLiveStatus("live", `Live · ${new Date().toLocaleTimeString()}`);
        } catch (error) {
            state.failures += 1;
            setLiveStatus("error", error.status === 429 ? "Rate limited · retrying" : "API unreachable · retrying");
        } finally {
            state.inFlight = false;
            schedule();
        }
    }

    function schedule() {
        clearTimeout(state.timer);
        if (state.paused || document.hidden) return;
        const delay = state.failures ? Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** state.failures) : POLL_MS;
        state.timer = setTimeout(poll, delay);
    }

    $("pauseBtn").addEventListener("click", () => {
        state.paused = !state.paused;
        $("pauseBtn").textContent = state.paused ? "Resume" : "Pause";
        $("pauseBtn").setAttribute("aria-pressed", String(state.paused));
        if (state.paused) {
            clearTimeout(state.timer);
            setLiveStatus("paused", "Paused");
        } else {
            poll();
        }
    });

    $("levelFilters").addEventListener("click", event => {
        const button = event.target.closest("[data-level]");
        if (!button) return;
        $("levelFilters").querySelectorAll("[data-level]").forEach(chip => chip.setAttribute("aria-pressed", String(chip === button)));
        state.levelFilter = button.dataset.level;
        renderFeed();
    });

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) clearTimeout(state.timer);
        else if (!state.paused) poll();
    });

    // ---------- boot ----------

    (async () => {
        try {
            const data = await apiJson("/api/detection/rules");
            data.rules.forEach(rule => state.rules.set(rule.id, rule));
        } catch (_error) { /* names fall back to rule ids */ }
        poll();
        loadCharts();
        setInterval(() => { if (!document.hidden && !state.paused) loadCharts(); }, CHART_REFRESH_MS);
    })();
})();
