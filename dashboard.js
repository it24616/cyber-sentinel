
document.addEventListener("DOMContentLoaded", function () {

    // Threat Detection Chart

    const threatCanvas = document.getElementById("threatChart");

    new Chart(threatCanvas, {

        type: "line",

        data: {
            labels: [
                "Mon", "Tue", "Wed",
                "Thu", "Fri", "Sat", "Sun"
            ],

            datasets: [{
                label: "Detected Threats",

                data: [12, 19, 8, 25, 17, 30, 22],

                borderColor: "#00e5a0",

                backgroundColor: "rgba(0, 229, 160, 0.12)",

                fill: true,

                tension: 0.4
            }]
        },

        options: {
            responsive: true,

            maintainAspectRatio: true,

            plugins: {
                legend: {
                    labels: {
                        color: "#ffffff"
                    }
                }
            },

            scales: {

                x: {
                    ticks: {
                        color: "#9baec1"
                    },

                    grid: {
                        color: "#24394e"
                    }
                },

                y: {
                    beginAtZero: true,

                    ticks: {
                        color: "#9baec1"
                    },

                    grid: {
                        color: "#24394e"
                    }
                }
            }
        }

    });


    // Threat Distribution Chart

    const distributionCanvas =
        document.getElementById("distributionChart");

    const distributionChart = new Chart(distributionCanvas, {

        type: "doughnut",

        data: {

            labels: [
                "Critical",
                "High",
                "Medium",
                "Low"
            ],

            datasets: [{

                data: [8, 24, 46, 50],

                backgroundColor: [
                    "#ff4d4d",
                    "#ff9b45",
                    "#f5bb55",
                    "#00e5a0"
                ],

                borderWidth: 0
            }]
        },

        options: {

            responsive: true,

            plugins: {

                legend: {
                    position: "bottom",

                    labels: {
                        color: "#ffffff",
                        padding: 15
                    }
                }
            }
        }

    });


    // Refresh Button

    const refreshBtn = document.getElementById("refreshBtn");

    async function loadDashboardData() {
        try {
            const [statsResponse, alertsResponse, userResponse] = await Promise.all([
                apiFetch("/api/stats"),
                apiFetch("/api/alerts?per_page=4"),
                apiFetch("/api/auth/me")
            ]);
            if (!statsResponse.ok || !alertsResponse.ok || !userResponse.ok) throw new Error("API unavailable");
            const stats = (await statsResponse.json()).stats;
            const alerts = (await alertsResponse.json()).alerts;
            const userData = await userResponse.json();
            const currentUser = userData.user;
            document.getElementById("profileName").textContent = currentUser.full_name;
            document.getElementById("profileRole").textContent = currentUser.role;
            document.getElementById("profileAvatar").textContent = currentUser.full_name.slice(0, 1).toUpperCase();
            document.getElementById("totalThreats").textContent = stats.total;
            document.getElementById("criticalAlerts").textContent = stats.by_risk_level.CRITICAL;
            document.getElementById("criticalRiskCount").textContent = stats.by_risk_level.CRITICAL;
            document.getElementById("highRiskCount").textContent = stats.by_risk_level.HIGH;
            document.getElementById("mediumRiskCount").textContent = stats.by_risk_level.MEDIUM;
            document.getElementById("lowRiskCount").textContent = stats.by_risk_level.LOW;
            distributionChart.data.datasets[0].data = ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(level => stats.by_risk_level[level]);
            distributionChart.update();
            const body = document.getElementById("recentAlertsBody");
            body.replaceChildren();
            alerts.forEach(alert => {
                const row = document.createElement("tr");
                ["#" + alert.id, (alert.detected_threats || []).join(", "), alert.risk_level,
                    new Date(alert.created_at).toLocaleString(), alert.status].forEach(value => {
                    const cell = document.createElement("td");
                    cell.textContent = value;
                    row.appendChild(cell);
                });
                body.appendChild(row);
            });
            if (!alerts.length) {
                const row = document.createElement("tr");
                const cell = document.createElement("td");
                cell.colSpan = 5;
                cell.textContent = "No alerts recorded yet.";
                row.appendChild(cell);
                body.appendChild(row);
            }
            document.getElementById("apiStatus").lastChild.textContent = " API Connected";
        } catch (_error) {
            document.getElementById("apiStatus").lastChild.textContent = " API Unavailable";
        }
    }

    refreshBtn.addEventListener("click", loadDashboardData);
    loadDashboardData();


    // Sidebar Active Menu

    const menuLinks =
        document.querySelectorAll(".sidebar-menu a");

    menuLinks.forEach(function (link) {

        link.addEventListener("click", function () {

            menuLinks.forEach(function (item) {

                item.classList.remove("active");

            });

            this.classList.add("active");

        });

    });


    // Logout Button

    const logoutBtn = document.getElementById("logoutBtn");

    logoutBtn.addEventListener("click", async function (event) {

        event.preventDefault();

        const confirmLogout =
            confirm("Are you sure you want to logout?");

        if (confirmLogout) {
            try {
                await apiFetch("/api/auth/logout", { method: "POST" });
            } catch (_error) {
                // The local session cookie expires with the browser if the API is unavailable.
            }
            sessionStorage.removeItem("cyberSentinelCsrf");
            window.location.href = "login.html";

        }

    });


    // Notification Button

    document.querySelector(".notification")
        .addEventListener("click", function () {

            alert("You are viewing the sample security notifications.");

        });


    console.log("CyberGuard Dashboard Loaded Successfully!");

});
