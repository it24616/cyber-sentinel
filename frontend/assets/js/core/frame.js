// Loaded first in the <head> of every page under pages/.
// - Opened directly (top level): redirect into the app shell so the sidebar is always present.
// - Inside the shell: mark the page as embedded and route page links through the shell.
(() => {
    const SHELL = "../app.html";
    const page = (window.location.pathname.split("/").pop() || "").replace(/\.html$/, "");

    let shellWindow = null;
    try {
        if (window.top !== window.self && window.top.CS_SHELL) shellWindow = window.top;
    } catch (_error) {
        shellWindow = null; // Framed by a different origin: leave the page alone.
    }

    if (window.top === window.self) {
        window.location.replace(`${SHELL}#/${page}${window.location.search}`);
        return;
    }
    if (!shellWindow) return;

    window.CS_EMBEDDED = true;
    document.documentElement.classList.add("cs-embedded");

    /** Navigate the shell. Accepts "#/route?query", "../app.html#/route" or a pages/*.html URL. */
    window.csNavigate = target => {
        if (typeof target === "string" && target.startsWith("#/")) {
            shellWindow.location.hash = target;
            return;
        }
        const url = new URL(target, window.location.href);
        const name = (url.pathname.split("/").pop() || "").replace(/\.html$/, "");
        if (url.origin !== window.location.origin) {
            shellWindow.open(url.href, "_blank", "noopener");
        } else if (name === "app") {
            shellWindow.location.hash = url.hash || "#/dashboard";
        } else if (url.pathname.includes("/pages/")) {
            shellWindow.location.hash = `#/${name}${url.search}`;
        } else {
            shellWindow.location.href = url.href;
        }
    };

    // Tell the shell that alert data changed (refreshes the notification badge).
    window.csNotifyChanged = () => {
        try { shellWindow.dispatchEvent(new Event("cs:data-changed")); } catch (_error) { /* ignore */ }
    };

    document.addEventListener("click", event => {
        if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
        const link = event.target.closest && event.target.closest("a[href]");
        if (!link || link.target === "_blank" || link.hasAttribute("download")) return;
        const href = link.getAttribute("href");
        if (href.startsWith("#") && !href.startsWith("#/")) return; // in-page anchor
        const url = new URL(href, window.location.href);
        if (url.origin !== window.location.origin) return;
        if (!href.startsWith("#/") && !url.pathname.endsWith(".html")) return;
        event.preventDefault();
        window.csNavigate(href.startsWith("#/") ? href : url.href);
    });
})();
