// Shared authenticated API client for the static frontend.
(() => {
    const host = window.location.hostname === "localhost" ? "localhost" : "127.0.0.1";
    const apiOrigin = window.location.port === "5500"
        ? `http://${host}:5000`
        : window.location.origin;
    window.API_ORIGIN = apiOrigin;
    let csrfRequest;
    window.apiFetch = async (input, options = {}) => {
        const url = new URL(input, apiOrigin);
        const headers = new Headers(options.headers || {});
        const method = (options.method || "GET").toUpperCase();
        let csrfToken = sessionStorage.getItem("cyberSentinelCsrf");
        if (!csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method) && !url.pathname.endsWith("/auth/login") && !url.pathname.endsWith("/auth/register")) {
            csrfRequest ||= fetch(`${apiOrigin}/api/auth/me`, { credentials: "include" })
                .then(response => response.ok ? response.json() : null)
                .then(data => {
                    if (data && data.csrf_token) sessionStorage.setItem("cyberSentinelCsrf", data.csrf_token);
                    return data && data.csrf_token;
                });
            csrfToken = await csrfRequest;
        }
        if (csrfToken && !["GET", "HEAD", "OPTIONS"].includes(method)) {
            headers.set("X-CSRF-Token", csrfToken);
        }
        const response = await fetch(url, { ...options, headers, credentials: "include" });
        const publicAuthRoute = url.pathname.endsWith("/auth/login") || url.pathname.endsWith("/auth/register");
        if (response.status === 401 && !publicAuthRoute) {
            sessionStorage.removeItem("cyberSentinelCsrf");
            window.location.href = "login.html";
        }
        return response;
    };
})();
