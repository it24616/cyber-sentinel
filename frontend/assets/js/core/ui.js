// Shared UI helpers: DOM building, formatting, toasts and accessible modals (window.csUI).
// Inside the app shell, modals and toasts render in the shell window so they cover the whole app.
(() => {
    const LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

    /** el("div", { class: "card", text: "…", onclick }, child, …) */
    function el(tag, props = {}, ...children) {
        const node = document.createElement(tag);
        for (const [key, value] of Object.entries(props || {})) {
            if (value === undefined || value === null || value === false) continue;
            if (key === "class") node.className = value;
            else if (key === "text") node.textContent = value;
            else if (key === "dataset") Object.assign(node.dataset, value);
            else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
            else if (value === true) node.setAttribute(key, "");
            else node.setAttribute(key, value);
        }
        for (const child of children.flat()) {
            if (child === undefined || child === null || child === false) continue;
            node.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return node;
    }

    const numberFormat = new Intl.NumberFormat();
    const formatNumber = value => numberFormat.format(Number(value) || 0);

    function relativeTime(iso) {
        if (!iso) return "never";
        const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
        if (!Number.isFinite(seconds)) return "";
        if (seconds < 10) return "just now";
        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
        if (seconds < 604800) return `${Math.floor(seconds / 86400)} d ago`;
        return new Date(iso).toLocaleDateString();
    }

    const formatDateTime = iso => (iso ? new Date(iso).toLocaleString() : "—");
    const titleCase = text => String(text || "").toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
    const tone = level => (LEVELS.includes(String(level).toUpperCase()) ? String(level).toLowerCase() : "info");

    function badge(level, text) {
        return el("span", { class: `badge badge-${tone(level)}`, text: text ?? String(level).toUpperCase() });
    }

    function timeEl(iso) {
        return el("time", { datetime: iso, title: formatDateTime(iso), text: relativeTime(iso), "data-relative": "" });
    }

    // Keep relative timestamps fresh without re-rendering.
    setInterval(() => {
        document.querySelectorAll("time[data-relative]").forEach(node => {
            node.textContent = relativeTime(node.getAttribute("datetime"));
        });
    }, 30000);

    function emptyState({ icon = "🛡", title, text, actions = [] }) {
        const row = el("div", { class: "row" });
        actions.forEach(action => {
            const className = `btn btn-sm ${action.primary ? "btn-primary" : "btn-secondary"}`;
            row.append(action.href
                ? el("a", { class: className, href: action.href, text: action.label })
                : el("button", { class: className, type: "button", text: action.label, onclick: action.onClick }));
        });
        return el("div", { class: "empty-state" },
            el("div", { class: "empty-state-icon", "aria-hidden": "true", text: icon }),
            title && el("h3", { text: title }),
            text && el("p", { text }),
            actions.length && row);
    }

    // ---------- toasts & modals (local implementations) ----------

    function toastRegion() {
        let region = document.querySelector(".toast-region");
        if (!region) {
            region = el("div", { class: "toast-region", role: "status", "aria-live": "polite" });
            document.body.appendChild(region);
        }
        return region;
    }

    function localToast(message, { tone: kind = "info", timeout = 4500 } = {}) {
        const close = el("button", { type: "button", "aria-label": "Dismiss", text: "×" });
        const node = el("div", { class: "toast", "data-tone": kind }, el("p", { text: message }), close);
        const remove = () => node.remove();
        close.addEventListener("click", remove);
        toastRegion().appendChild(node);
        if (timeout) setTimeout(remove, timeout);
    }

    /**
     * Opens a modal and resolves with the value passed to close().
     * build(api) returns { body: Node, footer: Node[] } and may focus an element.
     */
    function openModal(labelText, build) {
        return new Promise(resolve => {
            const previousFocus = document.activeElement;
            const titleId = `modal-title-${Date.now()}`;
            const dialog = el("div", { class: "modal", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId });
            const backdrop = el("div", { class: "modal-backdrop" }, dialog);

            let settled = false;
            function close(value) {
                if (settled) return;
                settled = true;
                backdrop.remove();
                document.removeEventListener("keydown", onKey, true);
                if (previousFocus && previousFocus.focus) previousFocus.focus();
                resolve(value);
            }

            const { body, footer, cancelValue } = build({ close, titleId });
            dialog.append(body, el("div", { class: "modal-footer" }, footer));

            function onKey(event) {
                if (event.key === "Escape") {
                    event.preventDefault();
                    close(cancelValue);
                } else if (event.key === "Tab") {
                    // Keep keyboard focus inside the dialog.
                    const focusable = [...dialog.querySelectorAll("button, input, textarea, select, a[href]")]
                        .filter(node => !node.disabled);
                    if (!focusable.length) return;
                    const first = focusable[0];
                    const last = focusable[focusable.length - 1];
                    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
                    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
                }
            }
            document.addEventListener("keydown", onKey, true);
            backdrop.addEventListener("mousedown", event => {
                if (event.target === backdrop) close(cancelValue);
            });
            document.body.appendChild(backdrop);
            (dialog.querySelector("[data-autofocus]") || dialog.querySelector("button")).focus();
        });
    }

    function localConfirm({ title, message, confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false }) {
        return openModal(title, ({ close, titleId }) => ({
            cancelValue: false,
            body: el("div", { class: "modal-body" },
                el("h2", { id: titleId, text: title }),
                message && el("p", { text: message })),
            footer: [
                el("button", { type: "button", class: "btn btn-secondary", text: cancelLabel, onclick: () => close(false) }),
                el("button", {
                    type: "button", class: `btn ${danger ? "btn-danger" : "btn-primary"}`, text: confirmLabel,
                    "data-autofocus": true, onclick: () => close(true),
                }),
            ],
        }));
    }

    function localPrompt({
        title, message, label = "Note", placeholder = "", initial = "", required = false,
        multiline = true, confirmLabel = "Save", cancelLabel = "Cancel", suggestions = [], maxLength = 2000,
    }) {
        return openModal(title, ({ close, titleId }) => {
            const inputId = `modal-input-${Date.now()}`;
            const errorId = `${inputId}-error`;
            const input = el(multiline ? "textarea" : "input", {
                id: inputId, class: multiline ? "textarea" : "input", placeholder, maxlength: String(maxLength),
                "aria-describedby": errorId, "data-autofocus": true,
            });
            if (multiline) input.style.minHeight = "96px";
            input.value = initial;
            const errorText = el("p", { id: errorId, class: "field-error", hidden: true });
            const chips = suggestions.length
                ? el("div", { class: "chip-group", style: "margin-top:10px" }, suggestions.map(text =>
                    el("button", {
                        type: "button", class: "chip", text,
                        onclick: () => { input.value = text; input.focus(); errorText.hidden = true; },
                    })))
                : null;

            function submit() {
                const value = input.value.trim();
                if (required && !value) {
                    errorText.textContent = `${label} is required.`;
                    errorText.hidden = false;
                    input.setAttribute("aria-invalid", "true");
                    input.focus();
                    return;
                }
                close(value);
            }
            input.addEventListener("input", () => { errorText.hidden = true; input.removeAttribute("aria-invalid"); });
            input.addEventListener("keydown", event => {
                if (event.key === "Enter" && (!multiline || event.ctrlKey || event.metaKey)) {
                    event.preventDefault();
                    submit();
                }
            });

            return {
                cancelValue: null,
                body: el("div", { class: "modal-body" },
                    el("h2", { id: titleId, text: title }),
                    message && el("p", { text: message }),
                    el("div", { class: "field" },
                        el("label", { for: inputId, text: required ? label : "" },
                            !required && label, !required && el("span", { class: "optional", text: " (optional)" })),
                        input, errorText),
                    chips),
                footer: [
                    el("button", { type: "button", class: "btn btn-secondary", text: cancelLabel, onclick: () => close(null) }),
                    el("button", { type: "button", class: "btn btn-primary", text: confirmLabel, onclick: submit }),
                ],
            };
        });
    }

    // Inside the app shell, delegate overlays to the shell window.
    let host = null;
    try {
        if (window.top !== window.self && window.top.CS_SHELL && window.top.csUI) host = window.top.csUI;
    } catch (_error) {
        host = null;
    }

    // Password visibility toggles: <button data-toggle-password="inputId">
    document.addEventListener("click", event => {
        const button = event.target.closest && event.target.closest("[data-toggle-password]");
        if (!button) return;
        const input = document.getElementById(button.dataset.togglePassword);
        if (!input) return;
        const show = input.type === "password";
        input.type = show ? "text" : "password";
        button.textContent = show ? "Hide" : "Show";
        button.setAttribute("aria-pressed", String(show));
    });

    window.csUI = {
        el, badge, timeEl, emptyState, relativeTime, formatDateTime, formatNumber, titleCase, tone, LEVELS,
        toast: host ? host.toast : localToast,
        confirm: host ? host.confirm : localConfirm,
        prompt: host ? host.prompt : localPrompt,
    };
})();
