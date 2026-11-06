const registerForm = document.getElementById("registerForm");
registerForm.addEventListener("submit", async event => {
    event.preventDefault();
    const message = document.getElementById("message");
    const password = document.getElementById("password").value;
    if (password.length < 12) {
        message.style.color = "#ff5c5c";
        message.textContent = "Use a password with at least 12 characters.";
        return;
    }
    if (password !== document.getElementById("confirmPassword").value) {
        message.style.color = "#ff5c5c";
        message.textContent = "Passwords do not match.";
        return;
    }
    if (!document.getElementById("terms").checked) {
        message.style.color = "#ff5c5c";
        message.textContent = "Please accept the Terms & Conditions.";
        return;
    }
    const submit = registerForm.querySelector('[type="submit"]');
    submit.disabled = true;
    message.textContent = "Creating your account…";
    try {
        const response = await apiFetch(`${API_ORIGIN}/api/auth/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                full_name: document.getElementById("fullname").value.trim(),
                email: document.getElementById("email").value.trim(),
                phone: document.getElementById("phone").value.trim(),
                password
            })
        });
        const data = await response.json();
        if (!response.ok || !data.success) throw new Error(data.error || "Account creation failed.");
        message.style.color = "#00e5a0";
        message.textContent = "Account created. Redirecting to sign in…";
        setTimeout(() => window.location.assign("login.html"), 900);
    } catch (error) {
        message.style.color = "#ff5c5c";
        message.textContent = error.message || "Could not reach the security service.";
    } finally {
        submit.disabled = false;
    }
});
