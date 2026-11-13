// Sign-in: on success, return to the page the user was on (?next=#/route) or the dashboard.
(() => {
    const form = document.getElementById("loginForm");
    const message = document.getElementById("message");

    function show(text, tone) {
        message.textContent = text;
        message.dataset.tone = tone;
    }

    function nextRoute() {
        const next = new URLSearchParams(window.location.search).get("next") || "";
        // Only in-app routes, never an arbitrary URL.
        return /^#\/[a-z-]+(\?[\w=&%.+-]*)?$/.test(next) ? next : "#/dashboard";
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;
        if (!email || !password) {
            show("Enter your email and password.", "error");
            return;
        }
        const submit = form.querySelector('[type="submit"]');
        submit.disabled = true;
        submit.classList.add("is-loading");
        show("Signing in…", "info");
        try {
            const data = await apiJson("/api/auth/login", { method: "POST", body: { email, password } });
            sessionStorage.setItem("cyberSentinelCsrf", data.csrf_token);
            show(`Welcome, ${data.user.full_name}.`, "success");
            window.location.assign(`app.html${nextRoute()}`);
        } catch (error) {
            show(error.status ? error.message : "Could not reach the security service. Is the API running?", "error");
            submit.disabled = false;
            submit.classList.remove("is-loading");
        }
    });

    const forgot = document.getElementById("forgotPassword");
    forgot.addEventListener("click", () => {
        const panel = document.getElementById("forgotPanel");
        panel.hidden = !panel.hidden;
        forgot.setAttribute("aria-expanded", String(!panel.hidden));
    });
})();
