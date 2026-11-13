// Chart.js presets that follow the design tokens in base.css (window.csCharts).
(() => {
    const css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
    const colors = () => ({
        text: css("--text-muted"),
        grid: css("--border"),
        accent: css("--accent"),
        levels: [css("--critical"), css("--high"), css("--medium"), css("--low")],
    });

    function line(canvas, { label, color } = {}) {
        const c = colors();
        const stroke = color || c.accent;
        return new Chart(canvas, {
            type: "line",
            data: { labels: [], datasets: [{
                label, data: [], borderColor: stroke, backgroundColor: `${stroke}22`, fill: true,
                tension: 0.35, cubicInterpolationMode: "monotone", pointRadius: 2, pointHoverRadius: 4, borderWidth: 2,
            }] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: c.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }, grid: { color: c.grid } },
                    y: { beginAtZero: true, ticks: { color: c.text, precision: 0 }, grid: { color: c.grid } },
                },
            },
        });
    }

    function severityDoughnut(canvas) {
        const c = colors();
        return new Chart(canvas, {
            type: "doughnut",
            data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{
                data: [0, 0, 0, 0], backgroundColor: c.levels, borderWidth: 0, hoverOffset: 4,
            }] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                plugins: { legend: { display: false } },
            },
        });
    }

    function setData(chart, labels, values) {
        if (labels) chart.data.labels = labels;
        chart.data.datasets[0].data = values;
        chart.update();
    }

    /** Severity counts [critical, high, medium, low]; shows a neutral ring when everything is zero. */
    function setSeverity(chart, values) {
        const empty = values.every(value => !value);
        const dataset = chart.data.datasets[0];
        dataset.data = empty ? [1] : values;
        dataset.backgroundColor = empty ? [css("--surface-3")] : colors().levels;
        chart.data.labels = empty ? ["No data yet"] : ["Critical", "High", "Medium", "Low"];
        chart.options.plugins.tooltip = { enabled: !empty };
        chart.update();
    }

    window.csCharts = { line, severityDoughnut, setData, setSeverity };
})();
