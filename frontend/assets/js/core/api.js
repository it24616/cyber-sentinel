// Shared authenticated API client: API origin, CSRF header, JSON helpers, 401 handling.
(() => {
    // Local dev: pages on :5500 call the Flask API directly. Port 5050 avoids macOS
    // AirPlay Receiver, which occupies :5000. Keep in sync with PORT in .env.
    // Override per browser without editing code: localStorage.cyberSentinelApiPort = "5051"
    const DEFAULT_DEV_API_PORT = "5050";
    const CSRF_KEY = "cyberSentinelCsrf";
    const SAFE_METHODS = ["GET", "HEAD", "OPTIONS"];
    const PUBLIC_AUTH_PATHS = ["/api/auth/login", "/api/auth/register"];

    let devApiPort = DEFAULT_DEV_API_PORT;
    try {
        devApiPort = localStorage.getItem("cyberSentinelApiPort") || DEFAULT_DEV_API_PORT;
    } catch (_error) { /* storage blocked: use the default */ }
    const host = window.location.hostname === "localhost" ? "localhost" : "127.0.0.1";
    // Elsewhere (Docker/Nginx) the API is served from the same origin under /api/.
    const apiOrigin = window.location.port === "5500" ? `http://${host}:${devApiPort}` : window.location.origin;
    window.API_ORIGIN = apiOrigin;

    // Root of the frontend (works for pages/ and top-level pages alike).
    const frontendRoot = new URL(window.location.pathname.includes("/pages/") ? "../" : "./", window.location.href);
    const loginUrl = () => {
        // Remember where the user was, so sign-in can return them there.
        let next = "";
        try {
            const top = window.top.location;
            if (/\/app\.html$/.test(top.pathname) && top.hash.startsWith("#/")) next = top.hash;
        } catch (_error) { /* not same-origin */ }
        return new URL(`login.html${next ? `?next=${encodeURIComponent(next)}` : ""}`, frontendRoot).href;
    };

    let csrfRequest;
    async function csrfToken() {
        let token = sessionStorage.getItem(CSRF_KEY);
        if (token) return token;
        csrfRequest ||= fetch(`${apiOrigin}/api/auth/me`, { credentials: "include" })
            .then(response => (response.ok ? response.json() : null))
            .then(data => {
                if (data && data.csrf_token) sessionStorage.setItem(CSRF_KEY, data.csrf_token);
                return data && data.csrf_token;
            })
            .finally(() => { csrfRequest = null; });
        return csrfRequest;
    }

    window.apiFetch = async (input, options = {}) => {
        const url = new URL(input, apiOrigin);
        const headers = new Headers(options.headers || {});
        const method = (options.method || "GET").toUpperCase();
        const publicAuthRoute = PUBLIC_AUTH_PATHS.some(path => url.pathname.endsWith(path));
        if (!SAFE_METHODS.includes(method) && !publicAuthRoute) {
            const token = await csrfToken();
            if (token) headers.set("X-CSRF-Token", token);
        }
        const response = await fetch(url, { ...options, headers, credentials: "include" });
        if (response.status === 401 && !publicAuthRoute) {
            sessionStorage.removeItem(CSRF_KEY);
            // Leave the whole app (not just an embedded frame) for the sign-in page.
            (window.CS_EMBEDDED ? window.top : window).location.href = loginUrl();
        }
        return response;
    };

    /** JSON request that resolves to the response body or throws Error(message) with .status. */
    window.apiJson = async (path, { method = "GET", body } = {}) => {
        const options = { method };
        if (body !== undefined) {
            options.headers = { "Content-Type": "application/json" };
            options.body = JSON.stringify(body);
        }
        const response = await window.apiFetch(path, options);
        const data = await response.json().catch(() => ({}));
        if (!response.ok || data.success === false) {
            const message = response.status === 429
                ? "Too many requests in a short time. Wait a moment and try again."
                : data.error || `Request failed (${response.status}).`;
            const error = new Error(message);
            error.status = response.status;
            throw error;
        }
        return data;
    };

    window.clearSession = () => sessionStorage.removeItem(CSRF_KEY);
})();
