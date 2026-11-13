// Integrations: create and revoke ingestion keys, and copy-ready code to send events.
(() => {
    const { el, badge, emptyState, formatDateTime, relativeTime } = window.csUI;
    const $ = id => document.getElementById(id);
    const endpoint = `${API_ORIGIN}/api/events/ingest`;
    let latestKey = "";

    // ---------- code examples ----------

    const SAMPLE_EVENT = {
        external_id: "evt-12345",
        event_type: "authentication_failure",
        observed_at: "2026-11-06T12:30:00Z",
        event_data: "Multiple failed login attempts for account admin",
    };

    const SNIPPETS = {
        curl: key => `curl -X POST ${endpoint} \\
  -H "Authorization: Bearer ${key}" \\
  -H "Content-Type: application/json" \\
  -d '${JSON.stringify({ events: [SAMPLE_EVENT] })}'`,
        python: key => `import os
import requests

API_KEY = os.environ.get("CYBER_SENTINEL_KEY", "${key}")

response = requests.post(
    "${endpoint}",
    headers={"Authorization": f"Bearer {API_KEY}"},
    json={"events": [{
        "external_id": "${SAMPLE_EVENT.external_id}",
        "event_type": "${SAMPLE_EVENT.event_type}",
        "observed_at": "${SAMPLE_EVENT.observed_at}",
        "event_data": "${SAMPLE_EVENT.event_data}",
    }]},
    timeout=10,
)
print(response.status_code, response.json())`,
        node: key => `const apiKey = process.env.CYBER_SENTINEL_KEY ?? "${key}";

const response = await fetch("${endpoint}", {
  method: "POST",
  headers: { Authorization: \`Bearer \${apiKey}\`, "Content-Type": "application/json" },
  body: JSON.stringify({ events: [${JSON.stringify(SAMPLE_EVENT)}] }),
});
console.log(response.status, await response.json());`,
    };

    let language = "curl";
    function renderSnippet() {
        $("snippetCode").textContent = SNIPPETS[language](latestKey || "YOUR_API_KEY");
        document.querySelectorAll(".tab").forEach(tab => {
            const selected = tab.dataset.lang === language;
            tab.setAttribute("aria-selected", String(selected));
            tab.tabIndex = selected ? 0 : -1;
            if (selected) $("snippet").setAttribute("aria-labelledby", tab.id);
        });
    }

    document.querySelector(".tabs").addEventListener("click", event => {
        const tab = event.target.closest(".tab");
        if (!tab) return;
        language = tab.dataset.lang;
        renderSnippet();
    });
    document.querySelector(".tabs").addEventListener("keydown", event => {
        if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
        const tabs = [...document.querySelectorAll(".tab")];
        const index = tabs.findIndex(tab => tab.dataset.lang === language);
        const next = tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
        language = next.dataset.lang;
        renderSnippet();
        next.focus();
    });

    async function copy(text, label) {
        try {
            await navigator.clipboard.writeText(text);
            csUI.toast(`${label} copied to the clipboard.`, { tone: "success" });
        } catch (_error) {
            csUI.toast("Copy failed. Select the text and copy it manually.", { tone: "error" });
        }
    }

    $("copySnippet").addEventListener("click", () => copy($("snippetCode").textContent, "Code example"));
    $("copyKey").addEventListener("click", () => copy($("newKeyValue").textContent, "API key"));

    // ---------- keys ----------

    function keyItem(key) {
        const status = key.revoked_at
            ? `Revoked ${relativeTime(key.revoked_at)}`
            : key.last_used_at ? `Last used ${relativeTime(key.last_used_at)}` : "Never used";
        return el("article", { class: `key-item${key.revoked_at ? " revoked" : ""}` },
            el("div", {},
                el("div", { class: "row" },
                    el("strong", { text: key.name }),
                    key.revoked_at ? badge("info", "REVOKED") : badge("LOW", "ACTIVE")),
                el("p", {}, el("code", { text: `${key.key_prefix}…` }), ` · Created ${formatDateTime(key.created_at)} · ${status}`)),
            !key.revoked_at && el("button", {
                type: "button", class: "btn btn-danger-ghost btn-sm", text: "Revoke", onclick: () => revoke(key),
            }));
    }

    async function loadKeys() {
        const list = $("keyList");
        try {
            const { api_keys: keys } = await apiJson("/api/integrations/keys");
            list.replaceChildren();
            if (!keys.length) {
                list.append(emptyState({
                    icon: "🔑", title: "No integration keys yet",
                    text: "Create one above, then use the code example to send your first event.",
                }));
                return;
            }
            keys.forEach(key => list.append(keyItem(key)));
        } catch (error) {
            list.replaceChildren(el("p", { class: "field-error", text: error.message }));
        }
    }

    async function revoke(key) {
        const confirmed = await csUI.confirm({
            title: `Revoke “${key.name}”?`,
            message: "Anything using this key will immediately stop sending events. This cannot be undone.",
            confirmLabel: "Revoke key", danger: true,
        });
        if (!confirmed) return;
        try {
            await apiJson(`/api/integrations/keys/${key.id}`, { method: "DELETE" });
            csUI.toast(`Key “${key.name}” revoked.`, { tone: "success" });
            await loadKeys();
        } catch (error) {
            csUI.toast(error.message, { tone: "error" });
        }
    }

    $("keyForm").addEventListener("submit", async event => {
        event.preventDefault();
        const form = event.currentTarget;
        const button = form.querySelector("button[type=submit]");
        const message = $("formMessage");
        const name = $("keyName").value.trim();
        if (!name) {
            message.dataset.tone = "error";
            message.textContent = "Give the integration a name.";
            $("keyName").focus();
            return;
        }
        button.disabled = true;
        button.classList.add("is-loading");
        message.textContent = "";
        $("newKeyNotice").hidden = true;
        try {
            const { api_key: key } = await apiJson("/api/integrations/keys", { method: "POST", body: { name } });
            latestKey = key.key;
            $("newKeyValue").textContent = key.key;
            $("newKeyNotice").hidden = false;
            form.reset();
            renderSnippet();
            await loadKeys();
        } catch (error) {
            message.dataset.tone = "error";
            message.textContent = error.message;
        } finally {
            button.disabled = false;
            button.classList.remove("is-loading");
        }
    });

    $("refreshKeys").addEventListener("click", loadKeys);
    renderSnippet();
    loadKeys();
})();
