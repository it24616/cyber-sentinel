const keyList = document.getElementById("keyList");
const formMessage = document.getElementById("formMessage");
const keyForm = document.getElementById("keyForm");
document.getElementById("ingestEndpoint").textContent = `${API_ORIGIN}/api/events/ingest`;

async function loadKeys() {
    keyList.textContent = "Loading integration keys…";
    try {
        const response = await apiFetch("/api/integrations/keys");
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Could not load keys.");
        keyList.replaceChildren();
        if (!data.api_keys.length) {
            keyList.textContent = "No integration keys yet.";
            return;
        }
        data.api_keys.forEach(key => {
            const item = document.createElement("article");
            item.className = `key-item${key.revoked_at ? " revoked" : ""}`;
            const info = document.createElement("div");
            const title = document.createElement("strong");
            title.textContent = key.name;
            const meta = document.createElement("p");
            meta.textContent = `${key.key_prefix}… · Created ${new Date(key.created_at).toLocaleString()} · ${key.revoked_at ? "Revoked" : key.last_used_at ? `Last used ${new Date(key.last_used_at).toLocaleString()}` : "Never used"}`;
            info.append(title, meta);
            item.appendChild(info);
            if (!key.revoked_at) {
                const revoke = document.createElement("button");
                revoke.type = "button";
                revoke.textContent = "Revoke";
                revoke.addEventListener("click", () => revokeKey(key.id));
                item.appendChild(revoke);
            }
            keyList.appendChild(item);
        });
    } catch (error) {
        keyList.textContent = error.message;
    }
}

async function revokeKey(id) {
    if (!confirm("Revoke this integration key? Collectors using it will stop ingesting events.")) return;
    try {
        const response = await apiFetch(`/api/integrations/keys/${id}`, { method: "DELETE" });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Could not revoke key.");
        await loadKeys();
    } catch (error) {
        formMessage.textContent = error.message;
    }
}

keyForm.addEventListener("submit", async event => {
    event.preventDefault();
    const button = keyForm.querySelector("button[type=submit]");
    const notice = document.getElementById("newKeyNotice");
    const output = document.getElementById("newKeyValue");
    button.disabled = true;
    formMessage.textContent = "Creating key…";
    notice.hidden = true;
    try {
        const response = await apiFetch("/api/integrations/keys", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ name: document.getElementById("keyName").value.trim() })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Could not create key.");
        output.textContent = data.api_key.key;
        notice.hidden = false;
        formMessage.textContent = "Key created.";
        keyForm.reset();
        await loadKeys();
    } catch (error) {
        formMessage.textContent = error.message;
    } finally {
        button.disabled = false;
    }
});

document.getElementById("copyKey").addEventListener("click", async () => {
    await navigator.clipboard.writeText(document.getElementById("newKeyValue").textContent);
    document.getElementById("copyKey").textContent = "Copied";
});
document.getElementById("refreshKeys").addEventListener("click", loadKeys);
loadKeys();
