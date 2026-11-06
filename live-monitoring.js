
// ======================================
// CYBERGUARD LIVE MONITORING
// JavaScript Functionality
// ======================================

// Monitoring Elements
const pauseBtn = document.getElementById("pauseBtn");
const resumeBtn = document.getElementById("resumeBtn");
const monitoringMessage = document.getElementById("monitoringMessage");

const eventList = document.getElementById("eventList");

const totalEventsElement = document.getElementById("totalEvents");
const totalThreatsElement = document.getElementById("totalThreats");
const criticalAlertsElement = document.getElementById("criticalAlerts");


// Monitoring State
let isMonitoring = true;

let totalEvents = 1248;
let totalThreats = 186;
let criticalAlerts = 23;


// Sample Security Events
const sampleEvents = [
    {
        type: "Suspicious Login Attempt",
        description: "Multiple failed login attempts detected",
        severity: "critical",
        ip: "203.0.113.45"
    },
    {
        type: "SQL Injection Pattern",
        description: "Potential SQL injection pattern detected",
        severity: "high",
        ip: "198.51.100.23"
    },
    {
        type: "Port Scanning Activity",
        description: "Multiple port access attempts detected",
        severity: "medium",
        ip: "192.0.2.78"
    },
    {
        type: "Unusual Traffic",
        description: "Abnormal traffic pattern detected",
        severity: "low",
        ip: "203.0.113.67"
    },
    {
        type: "XSS Pattern Detected",
        description: "Potential cross-site scripting pattern",
        severity: "high",
        ip: "198.51.100.56"
    }
];


// Update Statistics
function updateStatistics() {

    totalEventsElement.textContent = totalEvents;
    totalThreatsElement.textContent = totalThreats;
    criticalAlertsElement.textContent = criticalAlerts;

}


// Add New Event
function addSecurityEvent() {

    if (!isMonitoring) return;

    const event = sampleEvents[
        Math.floor(Math.random() * sampleEvents.length)
    ];

    const eventItem = document.createElement("div");

    eventItem.className = "event-item";

    eventItem.innerHTML = `
        <span class="severity ${event.severity}">
            ${event.severity.toUpperCase()}
        </span>

        <div>
            <h4>${event.type}</h4>
            <p>${event.description}</p>
        </div>

        <span class="event-ip">${event.ip}</span>
    `;

    eventList.prepend(eventItem);

    // Keep only the latest 8 events
    while (eventList.children.length > 8) {
        eventList.removeChild(eventList.lastElementChild);
    }

    totalEvents++;

    if (event.severity !== "low") {
        totalThreats++;
    }

    if (event.severity === "critical") {
        criticalAlerts++;
    }

    updateStatistics();

}


// Pause Monitoring
pauseBtn.addEventListener("click", function () {

    isMonitoring = false;

    monitoringMessage.textContent =
        "Monitoring paused. No new demo events will be added.";

});


// Resume Monitoring
resumeBtn.addEventListener("click", function () {

    isMonitoring = true;

    monitoringMessage.textContent =
        "Monitoring resumed. Demo events are being generated.";

});


// Automatic Demo Event Generation
setInterval(function () {

    addSecurityEvent();

}, 5000);


// ======================================
// THREAT TRENDS CHART
// ======================================

const trendCanvas = document.getElementById("threatTrendChart");

new Chart(trendCanvas, {

    type: "line",

    data: {

        labels: [
            "00:00",
            "04:00",
            "08:00",
            "12:00",
            "16:00",
            "20:00",
            "24:00"
        ],

        datasets: [
            {
                label: "Threats Detected",

                data: [12, 19, 10, 25, 18, 32, 22],

                borderColor: "#00d9ff",

                backgroundColor: "rgba(0, 217, 255, 0.12)",

                fill: true,

                tension: 0.4,

                borderWidth: 2
            }
        ]
    },

    options: {

        responsive: true,

        maintainAspectRatio: false,

        plugins: {

            legend: {
                labels: {
                    color: "#dceaff"
                }
            }

        },

        scales: {

            x: {
                ticks: {
                    color: "#8497b5"
                },
                grid: {
                    color: "rgba(255,255,255,0.05)"
                }
            },

            y: {
                beginAtZero: true,
                ticks: {
                    color: "#8497b5"
                },
                grid: {
                    color: "rgba(255,255,255,0.05)"
                }
            }

        }

    }

});


// ======================================
// THREAT DISTRIBUTION CHART
// ======================================

const distributionCanvas =
    document.getElementById("threatDistributionChart");

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

            data: [23, 45, 58, 60],

            backgroundColor: [
                "#ff5252",
                "#ffad42",
                "#ffe16b",
                "#42f5a7"
            ],

            borderWidth: 0

        }]

    },

    options: {

        responsive: true,

        maintainAspectRatio: false,

        plugins: {

            legend: {

                position: "bottom",

                labels: {
                    color: "#dceaff",
                    padding: 15
                }

            }

        }

    }

});


// Initial Statistics
updateStatistics();


// Initial Message
monitoringMessage.textContent =
    "Monitoring interface active. Sample events are running.";
