(function () {
  var chart = null;
  var filterSel = document.getElementById('filter');
  var lastUpdate = document.getElementById('lastUpdate');
  var severityClasses = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

  function fetchJSON(url) {
    return fetch(url).then(function (response) {
      if (!response.ok) throw new Error('Request failed (' + response.status + ')');
      return response.json();
    });
  }

  function buildAlertCard(alert) {
    var card = document.createElement('div');
    card.className = 'alert ' + (severityClasses[alert.severity] || 'unknown');
    var meta = document.createElement('div');
    meta.className = 'meta';
    meta.textContent = alert.time + ' — ' + alert.rule + ' — ' + alert.severity;
    var details = document.createElement('div');
    details.className = 'details';
    details.textContent = alert.details;
    card.appendChild(meta);
    card.appendChild(details);
    return card;
  }

  function updateCounters(alerts) {
    document.getElementById('total').textContent = String(alerts.length);
    var high = 0, med = 0, low = 0;
    alerts.forEach(function (alert) {
      if (alert.severity === 'HIGH') high++;
      else if (alert.severity === 'MEDIUM') med++;
      else if (alert.severity === 'LOW') low++;
    });
    document.getElementById('high').textContent = String(high);
    document.getElementById('med').textContent = String(med);
    document.getElementById('low').textContent = String(low);
  }

  function updateChart() {
    return fetchJSON('/api/summary').then(function (summary) {
      if (typeof Chart === 'undefined') return;
      var labels = Object.keys(summary);
      var values = labels.map(function (key) { return summary[key]; });
      if (!chart) {
        var context = document.getElementById('chart').getContext('2d');
        chart = new Chart(context, {
          type: 'bar',
          data: { labels: labels, datasets: [{ label: 'Alerts', data: values }] },
          options: { responsive: true }
        });
      } else {
        chart.data.labels = labels;
        chart.data.datasets[0].data = values;
        chart.update();
      }
    });
  }

  function fetchAlerts() {
    return fetchJSON('/api/alerts').then(function (data) {
      var alerts = Array.isArray(data) ? data : [];
      var filter = filterSel.value;
      var shown = alerts.filter(function (alert) {
        return filter === 'all' || alert.severity === filter;
      });
      var container = document.getElementById('alerts');
      container.replaceChildren.apply(container, shown.map(buildAlertCard));
      updateCounters(alerts);
      lastUpdate.textContent = 'Updated ' + new Date().toLocaleTimeString();
      return updateChart().catch(function () {});
    }).catch(function () {
      lastUpdate.textContent = 'Unable to load alerts. Check the local service.';
    });
  }

  filterSel.addEventListener('change', fetchAlerts);
  document.getElementById('refreshBtn').addEventListener('click', fetchAlerts);
  setInterval(fetchAlerts, 1500);
  fetchAlerts();
})();
