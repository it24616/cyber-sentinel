// Registration with friendly, field-level validation before the request is sent.
(() => {
    const form = document.getElementById("registerForm");
    const message = document.getElementById("message");
    const value = id => document.getElementById(id).value;

    function show(text, tone, fieldId) {
        message.textContent = text;
        message.dataset.tone = tone;
        form.querySelectorAll("[aria-invalid]").forEach(input => input.removeAttribute("aria-invalid"));
        if (fieldId) {
            const field = document.getElementById(fieldId);
            field.setAttribute("aria-invalid", "true");
            field.focus();
        }
    }

    function validate() {
        if (!value("fullname").trim()) return ["Enter your name.", "fullname"];
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value("email").trim())) return ["Enter a valid email address.", "email"];
        if (value("password").length < 12) return ["Use a password with at least 12 characters.", "password"];
        if (value("password") !== value("confirmPassword")) return ["The two passwords don't match.", "confirmPassword"];
        if (!document.getElementById("terms").checked) return ["Please accept the Terms & Conditions.", "terms"];
        return null;
    }

    form.addEventListener("submit", async event => {
        event.preventDefault();
        const problem = validate();
        if (problem) {
            show(problem[0], "error", problem[1]);
            return;
        }
        const submit = form.querySelector('[type="submit"]');
        submit.disabled = true;
        submit.classList.add("is-loading");
        show("Creating your account…", "info");
        try {
            await apiJson("/api/auth/register", {
                method: "POST",
                body: {
                    full_name: value("fullname").trim(),
                    email: value("email").trim(),
                    phone: value("phone").trim(),
                    password: value("password"),
                },
            });
            show("Account created. Taking you to sign in…", "success");
            setTimeout(() => window.location.assign("login.html"), 900);
        } catch (error) {
            show(error.status ? error.message : "Could not reach the security service. Is the API running?", "error");
            submit.disabled = false;
            submit.classList.remove("is-loading");
        }
    });
})();
