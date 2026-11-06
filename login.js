const loginForm = document.getElementById("loginForm");
loginForm.addEventListener("submit", async event => {
    event.preventDefault();
    const message = document.getElementById("message");
    const submit = loginForm.querySelector('[type="submit"]');
    submit.disabled = true;
    message.textContent = "Signing in…";
    try {
        const response = await apiFetch(`${API_ORIGIN}/api/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: document.getElementById("email").value.trim(),
                password: document.getElementById("password").value
            })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Sign in failed.");
        sessionStorage.setItem("cyberSentinelCsrf", data.csrf_token);
        message.style.color = "#00e5a0";
        message.textContent = `Welcome, ${data.user.full_name}.`;
        window.location.assign("dashboard.html");
    } catch (error) {
        message.style.color = "#ff5c5c";
        message.textContent = error.message || "Could not reach the security service.";
    } finally {
        submit.disabled = false;
    }
});

document.getElementById("forgotPassword").addEventListener("click", event => {
    event.preventDefault();
    alert("Password recovery is not configured. Contact your system administrator.");
});
