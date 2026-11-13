
// Landing page: API health indicator and smooth in-page scrolling.

const apiHealth = document.getElementById("apiHealthStatus");
const apiHealthText = document.getElementById("apiHealthText");
// API_ORIGIN comes from api.js, loaded before this script.
fetch(`${window.API_ORIGIN}/api/health`)
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

        const href = this.getAttribute('href');
        const target = href.startsWith('#') ? document.querySelector(href) : null;

        if (target) {
            event.preventDefault();

            target.scrollIntoView({
                behavior: 'smooth'
            });
        }

    });

});
