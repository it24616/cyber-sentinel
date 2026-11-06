
const loginForm = document.getElementById("loginForm");

loginForm.addEventListener("submit", function(event) {

    event.preventDefault();

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    const message = document.getElementById("message");

    if (email && password) {

        message.style.color = "#00e5a0";

        message.textContent =
            "Login form submitted successfully!";

        console.log("Email:", email);

    }

});

document.getElementById("forgotPassword")
    .addEventListener("click", function(event) {

        event.preventDefault();

        alert("Password recovery will be available soon.");

    });
