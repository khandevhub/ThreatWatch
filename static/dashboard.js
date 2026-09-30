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
    var soc = buildSocLine(alert);
    if (soc) card.appendChild(soc);
    card.appendChild(buildInvestigateButton(alert));
    return card;
  }

  function buildInvestigateButton(alert) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'investigate-btn';
    button.textContent = 'Investigate';
    button.addEventListener('click', function () {
      toggleInvestigation(alert.id, button);
    });
    return button;
  }

  function toggleInvestigation(alertId, button) {
    var existing = document.getElementById('investigation-' + alertId);
    if (existing) {
      existing.remove();
      button.textContent = 'Investigate';
      return;
    }
    button.textContent = 'Loading...';
    fetchJSON('/api/alerts/' + alertId + '/investigation').then(function (pkg) {
      var panel = buildInvestigationPanel(pkg);
      panel.id = 'investigation-' + alertId;
      var container = document.getElementById('alerts');
      var alertCard = button.closest('.alert');
      if (alertCard && alertCard.parentNode === container) {
        alertCard.parentNode.insertBefore(panel, alertCard.nextSibling);
      } else {
        container.appendChild(panel);
      }
      button.textContent = 'Close investigation';
    }).catch(function () {
      button.textContent = 'Investigation unavailable';
    });
  }

  function addSection(panel, title) {
    var heading = document.createElement('div');
    heading.className = 'inv-section-title';
    heading.textContent = title;
    panel.appendChild(heading);
    var body = document.createElement('div');
    body.className = 'inv-section';
    panel.appendChild(body);
    return body;
  }

  function addLines(container, lines) {
    lines.forEach(function (line) {
      var item = document.createElement('div');
      item.className = 'inv-line';
      item.textContent = line;
      container.appendChild(item);
    });
  }

  function buildInvestigationPanel(pkg) {
    var panel = document.createElement('div');
    panel.className = 'investigation';
    var evidence = (pkg && pkg.evidence) || {};
    var entities = evidence.entities || {};
    var risk = (pkg && pkg.risk) || {};

    var header = addSection(panel, 'Investigation — alert #' + ((pkg.alert || {}).alert_id));
    addLines(header, [
      'Status: ' + ((pkg.alert || {}).investigation_status || 'unknown'),
      'Risk: ' + (risk.score === null || risk.score === undefined ? 'unavailable' :
        risk.score + '/100 (' + (risk.band || 'unknown') + ')'),
    ]);
    if (risk.explanation) addLines(header, [risk.explanation]);

    var entityLines = [];
    Object.keys(entities).forEach(function (kind) {
      if (entities[kind] && entities[kind].length) {
        entityLines.push(kind.replace(/_/g, ' ') + ': ' + entities[kind].join(', '));
      }
    });
    if (entityLines.length) {
      var entityBody = addSection(panel, 'Evidence (entities)');
      addLines(entityBody, entityLines);
    }
    if (evidence.unavailable && evidence.unavailable.length) {
      var missing = addSection(panel, 'Evidence unavailable');
      addLines(missing, [evidence.unavailable.join(', ')]);
    }

    var intel = (pkg && pkg.threat_intel) || {};
    if (intel.matches && intel.matches.length) {
      var intelBody = addSection(panel, 'Threat intelligence');
      addLines(intelBody, intel.matches.map(function (match) {
        if (match.fields) {
          return 'stored enrichment: ' + Object.keys(match.fields)
            .map(function (key) { return key + '=' + match.fields[key]; }).join(', ');
        }
        return (match.known_malicious ? 'KNOWN ' : 'unknown ') +
          match.indicator_type + ' ' + match.indicator +
          ' (confidence ' + match.confidence + ')';
      }));
    }

    var mitre = (pkg && pkg.mitre) || {};
    if (mitre.techniques && mitre.techniques.length) {
      var mitreBody = addSection(panel, 'MITRE ATT&CK');
      addLines(mitreBody, mitre.techniques.map(function (technique) {
        return technique.technique_id + ' ' + (technique.technique_name || '') +
          (technique.suggested_next_step ? ' — ' + technique.suggested_next_step : '');
      }));
    }

    var related = (pkg && pkg.related_alerts) || {};
    if (related.alerts && related.alerts.length) {
      var relatedBody = addSection(panel, 'Related alerts');
      addLines(relatedBody, related.alerts.slice(0, 10).map(function (alert) {
        return '#' + alert.alert_id + ' ' + alert.rule + ' (' + alert.severity +
          ', ' + alert.relation + ')';
      }));
    }

    var timeline = (pkg && pkg.timeline) || {};
    if (timeline.entries && timeline.entries.length) {
      var timelineBody = addSection(panel, 'Timeline (' + timeline.total_events + ' events)');
      addLines(timelineBody, timeline.entries.slice(0, 10).map(function (entry) {
        return (entry.timestamp || '(no timestamp)') + ' — ' +
          (entry.event_type || '?') +
          (entry.src_ip ? ' — ' + entry.src_ip : '') +
          (entry.user ? ' — ' + entry.user : '');
      }));
    }

    var questions = (pkg && pkg.investigation_questions) || [];
    if (questions.length) {
      var questionBody = addSection(panel, 'Suggested next steps');
      addLines(questionBody, questions);
    }
    return panel;
  }

  function buildSocLine(alert) {
    var parts = [];
    if (alert.deterministic_risk_score !== null && alert.deterministic_risk_score !== undefined) {
      var band = alert.risk_band ? ' (' + alert.risk_band + ')' : '';
      parts.push('risk ' + alert.deterministic_risk_score + '/100' + band);
    }
    if (alert.jev_priority) {
      parts.push('jev: ' + alert.jev_priority);
    }
    if (alert.attack_category) {
      parts.push('category: ' + alert.attack_category);
    }
    if (alert.mitre_techniques && alert.mitre_techniques.length) {
      parts.push('ATT&CK: ' + alert.mitre_techniques.join(', '));
    }
    if (alert.investigation_status && alert.investigation_status !== 'new') {
      parts.push('status: ' + alert.investigation_status);
    }
    if (!parts.length) return null;
    var line = document.createElement('div');
    line.className = 'meta soc-line';
    line.textContent = parts.join(' \u00b7 ');
    return line;
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
