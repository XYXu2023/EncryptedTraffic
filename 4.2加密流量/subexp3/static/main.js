let compositionChart;
let portChart;

async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  return res.json();
}

const baseChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  resizeDelay: 100,
  animation: false,
  layout: { padding: 4 },
  plugins: {
    legend: {
      position: "bottom",
      labels: { boxWidth: 12, padding: 12 }
    }
  }
};

function upsertDoughnut(id, chart, labels, values) {
  const ctx = document.getElementById(id);
  if (!chart) {
    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data: values,
          backgroundColor: ["#2563eb", "#16a34a", "#f59e0b", "#dc2626", "#7c3aed", "#0891b2", "#64748b"]
        }]
      },
      options: {
        ...baseChartOptions,
        cutout: "58%"
      }
    });
  }
  chart.data.labels = labels;
  chart.data.datasets[0].data = values;
  chart.update("none");
  return chart;
}

function upsertBar(id, chart, labels, values) {
  const ctx = document.getElementById(id);
  if (!chart) {
    return new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{ label: "Flow count", data: values, backgroundColor: "#3b82f6" }]
      },
      options: {
        ...baseChartOptions,
        scales: {
          y: { beginAtZero: true, ticks: { precision: 0 } },
          x: { ticks: { maxRotation: 0, autoSkip: true } }
        }
      }
    });
  }
  chart.data.labels = labels;
  chart.data.datasets[0].data = values;
  chart.update("none");
  return chart;
}

async function refresh() {
  const health = await api("/health");
  document.getElementById("status").textContent = health.capture.running ? `${health.capture.mode} 运行中` : "已停止";
  document.getElementById("activeFlows").textContent = health.active_flows;
  document.getElementById("packets").textContent = health.capture.packet_total;
  document.getElementById("model").textContent = health.model_ready ? "已加载" : "降级规则";

  const comp = await api("/stats/traffic_composition");
  compositionChart = upsertDoughnut(
    "compositionChart",
    compositionChart,
    comp.items.map(x => x.label),
    comp.items.map(x => x.count)
  );

  const env = await api("/stats/environment_summary");
  portChart = upsertBar(
    "portChart",
    portChart,
    env.top_ports.map(x => x.port),
    env.top_ports.map(x => x.count)
  );

  const recent = await api("/recent_predictions");
  const rows = document.getElementById("predictionRows");
  rows.innerHTML = "";
  recent.slice(0, 30).forEach(item => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${item.flow_id}</td><td>${item.src}</td><td>${item.dst}</td><td>${item.protocol}</td><td>${item.packet_count}</td><td>${item.predicted_label}</td><td>${Number(item.confidence).toFixed(3)}</td>`;
    rows.appendChild(tr);
  });

  const alerts = await api("/alerts");
  const box = document.getElementById("alerts");
  box.innerHTML = "";
  if (!alerts.length) {
    box.innerHTML = `<div class="empty">暂无告警</div>`;
  } else {
    alerts.slice(0, 20).forEach(a => {
      const div = document.createElement("div");
      div.className = `alert ${a.severity}`;
      div.innerHTML = `<strong>${a.alert_type}</strong> · ${a.time}<br>${a.message}<br><small>${a.flow_id}</small>`;
      box.appendChild(div);
    });
  }
}

document.getElementById("startBtn").addEventListener("click", async () => {
  await api("/start_capture", {
    method: "POST",
    body: JSON.stringify({
      mode: document.getElementById("mode").value,
      interface: document.getElementById("iface").value
    })
  });
  refresh();
});

document.getElementById("stopBtn").addEventListener("click", async () => {
  await api("/stop_capture", { method: "POST", body: "{}" });
  refresh();
});

refresh();
setInterval(refresh, 1500);
