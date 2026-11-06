
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

    new Chart(distributionCanvas, {

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

    refreshBtn.addEventListener("click", function () {

        refreshBtn.textContent = "↻ Demo Refreshed";

        setTimeout(function () {

            refreshBtn.textContent = "↻ Refresh";

        }, 1500);

    });


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

    logoutBtn.addEventListener("click", function (event) {

        event.preventDefault();

        const confirmLogout =
            confirm("Are you sure you want to logout?");

        if (confirmLogout) {

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
