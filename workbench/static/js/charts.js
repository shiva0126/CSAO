function renderCharts() {
  document.querySelectorAll("canvas[data-chart]").forEach((canvas) => {
    if (canvas.dataset.chartRendered === "true") {
      return;
    }
    const chartType = canvas.dataset.chart;
    const labels = JSON.parse(canvas.dataset.labels || "[]");
    const values = JSON.parse(canvas.dataset.values || "[]");
    const config = {
      type: chartType,
      data: {
        labels,
        datasets: [{
          label: "Count",
          data: values,
          backgroundColor: ["#4F8EF7", "#EF4444", "#F59E0B", "#6B7280", "#22C55E"],
          borderColor: ["#4F8EF7", "#EF4444", "#F59E0B", "#6B7280", "#22C55E"],
          borderWidth: chartType === "bar" ? 1 : 0,
          hoverBackgroundColor: ["#4F8EF7", "#EF4444", "#F59E0B", "#6B7280", "#22C55E"],
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "#151C28",
            borderColor: "#273244",
            borderWidth: 1,
            titleColor: "#F3F4F6",
            bodyColor: "#D1D5DB",
            displayColors: false,
          },
        },
      },
    };
    if (chartType === "bar") {
      config.options.scales = {
        x: {
          ticks: { color: "#9CA3AF" },
          grid: { display: false, drawBorder: false },
        },
        y: {
          beginAtZero: true,
          ticks: { precision: 0, color: "#9CA3AF" },
          grid: { color: "rgba(156, 163, 175, 0.12)", drawBorder: false },
        },
      };
    }
    if (chartType === "doughnut") {
      config.options.cutout = "68%";
    }
    new Chart(canvas.getContext("2d"), config);
    canvas.dataset.chartRendered = "true";
  });
}

document.addEventListener("DOMContentLoaded", renderCharts);
document.addEventListener("htmx:afterSwap", renderCharts);
