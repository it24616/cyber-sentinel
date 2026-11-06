
// CyberGuard Landing Page

console.log("CyberGuard System Loaded Successfully!");

const apiHealth = document.getElementById("apiHealthStatus");
const apiHealthText = document.getElementById("apiHealthText");
const apiHost = window.location.hostname === "localhost" ? "localhost" : "127.0.0.1";
const apiOrigin = window.location.port === "5500"
    ? `http://${apiHost}:5000`
    : window.location.origin;
fetch(`${apiOrigin}/api/health`)
    .then(response => {
        if (!response.ok) throw new Error("API unavailable");
        return response.json();
    })
    .then(() => {
        apiHealthText.textContent = "Assessment API online";
    })
    .catch(() => {
        apiHealth.classList.add("status-error");
        apiHealthText.textContent = "Assessment API offline";
    });

// Smooth scrolling for navigation links

document.querySelectorAll('.nav-links a').forEach(link => {

    link.addEventListener('click', function(event) {

        const target = document.querySelector(
            this.getAttribute('href')
        );

        if (target) {
            event.preventDefault();

            target.scrollIntoView({
                behavior: 'smooth'
            });
        }

    });

});
