
const registerForm = document.getElementById("registerForm");

registerForm.addEventListener("submit", function(event) {

    event.preventDefault();

    // Get form values

    const fullname = document.getElementById("fullname").value.trim();
    const email = document.getElementById("email").value.trim();
    const phone = document.getElementById("phone").value.trim();
    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const terms = document.getElementById("terms").checked;

    const message = document.getElementById("message");

    // Password length validation

    if (password.length < 8) {

        message.style.color = "#ff5c5c";
        message.textContent =
            "Password must contain at least 8 characters.";

        return;
    }

    // Password matching validation

    if (password !== confirmPassword) {

        message.style.color = "#ff5c5c";
        message.textContent =
            "Password and Confirm Password do not match!";

        return;
    }

    // Terms validation

    if (!terms) {

        message.style.color = "#ff5c5c";
        message.textContent =
            "Please accept the Terms & Conditions.";

        return;
    }

    // Registration demo message

    message.style.color = "#00e5a0";

    message.textContent =
        "Form validation successful! Backend registration is not connected yet.";

    console.log("Name:", fullname);
    console.log("Email:", email);
    console.log("Phone:", phone);

});
