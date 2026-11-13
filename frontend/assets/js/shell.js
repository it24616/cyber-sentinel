// App shell: hash router, page frame, account menu and unread-alert notifications.
// Routes look like "#/alerts?status=Open"; the query is passed on to the page.
window.CS_SHELL = true;

(() => {
    const ROUTES = {
        dashboard: { label: "Dashboard", page: "dashboard" },
        "live-detection": { label: "Live Detection", page: "live-detection" },
        alerts: { label: "Security Alerts", page: "alerts" },
        activities: { label: "Recent Activities", page: "dashboard", anchor: "activities" },
        analyze: { label: "Analyze Event", page: "analyze" },
        integrations: { label: "Integrations", page: "integrations" },
    };
    // Old page names keep working (bookmarks, earlier links).
    const ALIASES = {
        overview: "dashboard",
        "threat-detection": "live-detection",
        "live-monitoring": "live-detection",
        "risk-assessment": "analyze",
        "security-alerts": "alerts",
    };
    const NOTIFY_REFRESH_MS = 30000;

    const { el, badge, relativeTime } = window.csUI;
    const $ = id => document.getElementById(id);
    const frame = $("pageFrame");
    const progress = $("frameProgress");
    const navLinks = [...document.querySelectorAll(".nav a[data-route]")];

    navLinks.forEach(link => { link.title = link.textContent.trim(); });

    // ---------- routing ----------

    function parseHash() {
        const match = window.location.hash.match(/^#\/([a-z-]+)(\?[^#]*)?/);
        return { name: match ? match[1] : "dashboard", query: match && match[2] ? match[2] : "" };
    }

    function render() {
        let { name, query } = parseHash();
        if (ALIASES[name]) {
            window.location.replace(`#/${ALIASES[name]}${query}`);
            return;
        }
        if (!ROUTES[name]) name = "dashboard";
        const route = ROUTES[name];

        navLinks.forEach(link => {
            if (link.dataset.route === name) link.setAttribute("aria-current", "page");
            else link.removeAttribute("aria-current");
        });
        $("pageTitle").textContent = route.label;
        document.title = `${route.label} | Cyber Sentinel`;
        frame.title = route.label;
        closePopovers();

        const src = `pages/${route.page}.html${query}`;
        if (frame.dataset.src === src) {
            // Same page already loaded: only move to the requested section.
            try {
                const doc = frame.contentDocument;
                if (route.anchor) doc.getElementById(route.anchor)?.scrollIntoView({ behavior: "smooth" });
                else frame.contentWindow.scrollTo({ top: 0, behavior: "smooth" });
            } catch (_error) { /* not loaded yet */ }
            return;
        }
        frame.dataset.src = src;
        frame.dataset.anchor = route.anchor || "";
        progress.hidden = false;
        frame.src = src;
    }

    frame.addEventListener("load", () => {
        progress.hidden = true;
        const anchor = frame.dataset.anchor;
        if (anchor) {
            try { frame.contentDocument.getElementById(anchor)?.scrollIntoView(); } catch (_error) { /* ignore */ }
        }
    });

    window.addEventListener("hashchange", render);

    // ---------- popovers ----------

    const popovers = [
        { button: $("notificationBtn"), panel: $("notificationPanel") },
        { button: $("profileBtn"), panel: $("profileMenu") },
    ];

    function closePopovers(except) {
        popovers.forEach(({ button, panel }) => {
            if (panel === except) return;
            panel.hidden = true;
            button.setAttribute("aria-expanded", "false");
        });
    }

    popovers.forEach(({ button, panel }) => {
        button.addEventListener("click", event => {
            event.stopPropagation();
            const open = panel.hidden;
            closePopovers(panel);
            panel.hidden = !open;
            button.setAttribute("aria-expanded", String(open));
            if (open && panel.id === "notificationPanel") loadNotifications();
        });
        panel.addEventListener("click", event => event.stopPropagation());
    });
    document.addEventListener("click", () => closePopovers());
    // Clicks inside the page frame do not reach this document; close when it takes focus.
    window.addEventListener("blur", () => setTimeout(() => {
        if (document.activeElement === frame) closePopovers();
    }));
    document.addEventListener("keydown", event => {
        if (event.key === "Escape") closePopovers();
    });

    // ---------- account ----------

    async function loadAccount() {
        try {
            const { user } = await apiJson("/api/auth/me");
            $("profileName").textContent = user.full_name;
            $("profileMenuName").textContent = user.full_name;
            $("profileRole").textContent = user.role;
            $("profileEmail").textContent = user.email;
            $("profileAvatar").textContent = user.full_name.trim().charAt(0).toUpperCase() || "?";
        } catch (_error) {
            $("profileName").textContent = "Offline";
        }
    }

    $("logoutBtn").addEventListener("click", async () => {
        closePopovers();
        const confirmed = await csUI.confirm({
            title: "Sign out?",
            message: "You will need to sign in again to view alerts.",
            confirmLabel: "Sign out",
        });
        if (!confirmed) return;
        try {
            await apiJson("/api/auth/logout", { method: "POST" });
        } catch (_error) {
            // The session cookie expires on its own if the API is unavailable.
        }
        clearSession();
        window.location.href = "login.html";
    });

    // ---------- notifications (unread alerts) ----------

    let unread = [];
    let notifyLoading = false;

    function renderNotifications(alerts, total) {
        unread = alerts;
        const count = $("notificationCount");
        count.hidden = total === 0;
        count.textContent = total > 99 ? "99+" : String(total);
        $("notificationBtn").setAttribute("aria-label", `${total} unread alert${total === 1 ? "" : "s"}`);
        $("markAllReadBtn").disabled = !alerts.length;

        const list = $("notificationList");
        list.replaceChildren();
        if (!alerts.length) {
            list.append(el("li", { class: "empty-inline", text: "You're all caught up." }));
            return;
        }
        alerts.forEach(alert => {
            const item = el("button", {
                type: "button", class: "notification-item",
                onclick: async () => {
                    await markRead([alert.id]);
                    closePopovers();
                    window.location.hash = "#/alerts";
                },
            },
            el("span", { class: "notification-title" },
                badge(alert.risk_level),
                el("span", { text: `#${alert.id} ${(alert.detected_threats || []).join(", ")}` })),
            el("span", { class: "notification-meta", text: `${alert.source || "manual"} · ${relativeTime(alert.created_at)}` }));
            list.append(el("li", {}, item));
        });
    }

    async function loadNotifications() {
        if (notifyLoading) return;
        notifyLoading = true;
        try {
            const data = await apiJson("/api/alerts?is_read=false&per_page=8");
            renderNotifications(data.alerts, data.pagination.total);
        } catch (_error) {
            /* keep the last known state */
        } finally {
            notifyLoading = false;
        }
    }

    async function markRead(ids) {
        await Promise.allSettled(ids.map(id => apiJson(`/api/alerts/${id}`, { method: "PATCH", body: { is_read: true } })));
        await loadNotifications();
        // Let the visible page refresh its own view of the alerts.
        try { frame.contentWindow.dispatchEvent(new Event("cs:data-changed")); } catch (_error) { /* ignore */ }
    }

    $("markAllReadBtn").addEventListener("click", async () => {
        await markRead(unread.map(alert => alert.id));
        csUI.toast("All listed alerts marked as read.", { tone: "success" });
    });

    // Pages call csNotifyChanged() after changing alerts.
    window.addEventListener("cs:data-changed", loadNotifications);
    setInterval(() => {
        if (!document.hidden) loadNotifications();
    }, NOTIFY_REFRESH_MS);

    // ---------- boot ----------

    document.addEventListener("DOMContentLoaded", () => {
        render();
        loadAccount();
        loadNotifications();
    });
})();
