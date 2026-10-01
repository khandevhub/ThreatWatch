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
    loadAiInvestigation((pkg.alert || {}).alert_id, panel);
    return panel;
  }

  // -- Phase 4E-4K: advisory AI section (labeled AI-GENERATED; safe DOM only) --

  function loadAiInvestigation(alertId, panel) {
    if (typeof alertId !== 'number' || !alertId) return;
    fetchJSON('/api/alerts/' + alertId + '/ai-investigation').then(function (ai) {
      var body = addSection(panel, 'AI investigation \u2014 AI-GENERATED / ADVISORY');
      body.className += ' ai-advisory';
      if (!ai || ai.status !== 'ok') {
        addLines(body, ['AI status: ' + ((ai && ai.status) || 'unavailable') +
          (ai && ai.reason ? ' (' + ai.reason + ')' : '')]);
        return;
      }
      addLines(body, aiLines(ai));
    }).catch(function () {
      var body = addSection(panel, 'AI investigation \u2014 AI-GENERATED / ADVISORY');
      body.className += ' ai-advisory';
      addLines(body, ['AI status: unavailable']);
    });
  }

  function aiLines(ai) {
    var response = ai.response || {};
    var model = (ai.model || {}).model || 'unknown model';
    var lines = [
      'AI status: ok (model ' + model + ') \u2014 advisory only, can be wrong',
      'Summary: ' + (response.summary || '(none)'),
      'Assessment: ' + (response.assessment || '(none)'),
      'AI priority: ' + (response.priority || 'unknown') +
        ' | malicious likelihood: ' + formatLikelihood(response.malicious_likelihood) +
        ' | false-positive likelihood: ' + formatLikelihood(response.false_positive_likelihood) +
        ' | confidence: ' + formatLikelihood(response.confidence),
    ];
    if (ai.jev_context && ai.jev_context.priority) {
      lines.push('Jev decision (deterministic, not AI): ' + ai.jev_context.priority);
    }
    (response.key_evidence || []).slice(0, 10).forEach(function (item, index) {
      lines.push('Key evidence ' + (index + 1) + ': ' + item);
    });
    (response.mitre_assessment || []).slice(0, 10).forEach(function (entry) {
      lines.push('ATT&CK ' + entry.technique_id + ': ' + entry.relevance +
        (entry.rationale ? ' \u2014 ' + entry.rationale : ''));
    });
    (response.recommended_actions || []).slice(0, 10).forEach(function (action, index) {
      lines.push('Recommended step ' + (index + 1) + ': ' + (action.action || '') +
        (action.reason ? ' \u2014 ' + action.reason : ''));
    });
    if (response.source_references && response.source_references.length) {
      response.source_references.slice(0, 10).forEach(function (reference) {
        lines.push('Source (' + reference.type + '): ' + reference.value);
      });
    } else {
      lines.push('Sources: none cited by the model for this assessment');
    }
    return lines;
  }

  function formatLikelihood(value) {
    return (value === null || value === undefined) ? '?' : String(value);
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

  // -- Phase 5: SOAR section (read-only, safe DOM rendering) ------------

  function soarLine(text, className) {
    var div = document.createElement('div');
    div.className = className || 'meta';
    div.textContent = String(text == null ? '' : text);
    return div;
  }

  function soarStateChip(state) {
    var chip = document.createElement('span');
    chip.className = 'soar-chip ' +
      (state === 'SUCCEEDED' ? 'soar-ok' :
        state === 'RUNNING' || state === 'APPROVED' ? 'soar-run' :
        state === 'WAITING_APPROVAL' || state === 'PENDING' ? 'soar-wait' :
        'soar-bad');
    chip.textContent = String(state || '?');
    return chip;
  }

  function soarFillList(id, rows, build) {
    var container = document.getElementById(id);
    if (!container) return;
    var children = rows.map(build);
    if (!children.length) {
      children = [soarLine('No records.', 'meta')];
    }
    container.replaceChildren.apply(container, children);
  }

  function buildPlaybookRow(playbook) {
    var wrap = document.createElement('div');
    wrap.className = 'soar-item';
    var title = document.createElement('div');
    title.appendChild(soarStateChip(playbook.enabled ? 'ENABLED' : 'DISABLED'));
    title.appendChild(soarLine(
      playbook.playbook_id + ' v' + playbook.version + ' — ' + playbook.name +
      ' (approval: ' + playbook.definition.approval_policy + ')'));
    wrap.appendChild(title);
    return wrap;
  }

  function buildExecutionRow(execution) {
    var wrap = document.createElement('div');
    wrap.className = 'soar-item';
    var head = document.createElement('div');
    head.appendChild(soarStateChip(execution.state));
    head.appendChild(soarLine(
      execution.execution_id + ' — ' + execution.playbook_id +
      ' v' + execution.playbook_version + ' · alert #' + execution.alert_id));
    head.appendChild(soarLine(execution.dry_run ? 'DRY RUN' : 'REAL EXECUTION',
      execution.dry_run ? 'meta soar-dry' : 'meta soar-real'));
    if (execution.error) {
      head.appendChild(soarLine(execution.error, 'meta soar-err'));
    }
    wrap.appendChild(head);
    return wrap;
  }

  function buildApprovalRow(approval) {
    var wrap = document.createElement('div');
    wrap.className = 'soar-item';
    wrap.appendChild(soarStateChip(approval.decision));
    wrap.appendChild(soarLine(
      approval.approval_id + ' — ' + approval.action_type +
      ' (role: ' + approval.required_role + ', requested ' +
      approval.requested_at + ')'));
    return wrap;
  }

  function buildIncidentRow(incident) {
    var wrap = document.createElement('div');
    wrap.className = 'soar-item';
    wrap.appendChild(soarStateChip(incident.status));
    wrap.appendChild(soarLine(
      incident.incident_id + ' — ' + incident.title + ' [' +
      incident.severity + '] alerts: ' + (incident.alert_ids || []).join(', ')));
    return wrap;
  }

  function buildAuditRow(entry) {
    var wrap = document.createElement('div');
    wrap.className = 'soar-item';
    wrap.appendChild(soarLine(
      entry.created_at + ' — ' + entry.actor + ' — ' + entry.event_type +
      (entry.from_state ? ' · ' + entry.from_state + ' → ' + entry.to_state : '') +
      (entry.dry_run ? ' · DRY RUN' : ' · REAL'), 'meta'));
    if (entry.failure_reason) {
      wrap.appendChild(soarLine(entry.failure_reason, 'meta soar-err'));
    }
    return wrap;
  }

  function fetchSoar() {
    var playbooks = fetchJSON('/api/playbooks').then(function (data) {
      soarFillList('soar-playbooks', data.playbooks || [], buildPlaybookRow);
    });
    var executions = fetchJSON('/api/soar/executions?limit=10').then(function (data) {
      soarFillList('soar-executions', data.executions || [], buildExecutionRow);
    });
    var approvals = fetchJSON('/api/soar/approvals?decision=pending&limit=10')
      .then(function (data) {
        soarFillList('soar-approvals', data.approvals || [], buildApprovalRow);
      });
    var incidents = fetchJSON('/api/incidents?limit=10').then(function (data) {
      soarFillList('soar-incidents', data.incidents || [], buildIncidentRow);
    });
    var audit = fetchJSON('/api/soar/executions').then(function (data) {
      var ids = (data.executions || []).slice(0, 10)
        .map(function (execution) { return execution.execution_id; });
      return Promise.all(ids.map(function (id) {
        return fetchJSON('/api/soar/executions/' + encodeURIComponent(id) +
          '/audit');
      })).then(function (batches) {
        var rows = [].concat.apply([], batches.map(function (batch) {
          return batch.audit || [];
        }));
        soarFillList('soar-audit', rows, buildAuditRow);
      });
    });
    return Promise.all([
      playbooks, executions, approvals, incidents,
      audit.catch(function () { soarFillList('soar-audit', [], buildAuditRow); })
    ]).catch(function () {
      ['soar-playbooks', 'soar-executions', 'soar-approvals',
        'soar-incidents'].forEach(function (id) {
        soarFillList(id, [], function () {
          return soarLine('SOAR data unavailable.', 'meta');
        });
      });
    });
  }

  filterSel.addEventListener('change', fetchAlerts);
  document.getElementById('refreshBtn').addEventListener('click', fetchAlerts);
  setInterval(fetchAlerts, 1500);
  fetchAlerts();
  fetchSoar();
  setInterval(fetchSoar, 5000);
})();
