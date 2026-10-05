(function () {
  'use strict';
  var chart = null;
  var filterSel = document.getElementById('filter');
  var lastUpdate = document.getElementById('lastUpdate');
  var tokenInput = document.getElementById('console-token');
  var currentAlertId = null;
  var currentRunId = null;
  var severityClasses = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

  function authHeaders() {
    var headers = { 'Content-Type': 'application/json' };
    var token = tokenInput && tokenInput.value.trim();
    if (token) headers.Authorization = 'Bearer ' + token;
    return headers;
  }

  function fetchJSON(url, options) {
    options = options || {};
    if (options.headers === undefined) options.headers = {};
    return fetch(url, options).then(function (response) {
      if (!response.ok) {
        return response.json().catch(function () { return {}; }).then(function (body) {
          var message = body.message || body.error || ('HTTP ' + response.status);
          throw new Error(message);
        });
      }
      return response.json();
    });
  }

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function line(text, className) {
    return el('div', className || 'meta', text);
  }

  function addSection(panel, title, className) {
    var heading = el('div', 'inv-section-title', title);
    var body = el('div', 'inv-section' + (className ? ' ' + className : ''));
    panel.appendChild(heading);
    panel.appendChild(body);
    return body;
  }

  function addLines(container, lines) {
    lines.forEach(function (line) {
      var item;
      if (line && line.nodeType) {
        item = line;
      } else {
        item = el('div', 'inv-line');
        item.textContent = line;
      }
      container.appendChild(item);
    });
  }

  function textLines(values) {
    return (values || []).map(function (value) { return line(value); });
  }

  // ------------------------------------------------------------------
  // SOC overview metrics
  // ------------------------------------------------------------------

  function updateOverview() {
    return fetchJSON('/api/soc/overview').then(function (overview) {
      var ids = {
        total_alerts: 'soc-total', high_alerts: 'soc-high',
        medium_alerts: 'soc-med', low_alerts: 'soc-low',
        active_investigations: 'soc-active-inv',
        open_incidents: 'soc-open-inc',
        pending_approvals: 'soc-pending-approvals',
        running_executions: 'soc-running-exec',
        ai_investigations: 'soc-ai-inv',
        detection_events: 'soc-detection-events',
      };
      Object.keys(ids).forEach(function (key) {
        var node = document.getElementById(ids[key]);
        if (node) node.textContent = String(overview[key]);
      });
      // Top command-bar counters mirror the same real data.
      var critical = overview.critical_alerts || 0;
      var high = overview.high_alerts || 0;
      var critHigh = document.getElementById('tb-crit-high');
      if (critHigh) {
        critHigh.textContent = (critical + high) + ' crit/high';
        critHigh.className = 'tb-counter' + ((critical + high) > 0 ? ' tb-crit' : '');
      }
      var tbAlerts = document.getElementById('tb-alerts');
      if (tbAlerts) tbAlerts.textContent = String(overview.total_alerts || 0);
      var tbEvents = document.getElementById('tb-events');
      if (tbEvents) tbEvents.textContent = String(overview.detection_events || 0);
      var tbInv = document.getElementById('tb-investigations');
      if (tbInv) tbInv.textContent = String(overview.active_investigations || 0);
      var tbInc = document.getElementById('tb-incidents');
      if (tbInc) tbInc.textContent = String(overview.open_incidents || 0);
      var tbAppr = document.getElementById('tb-approvals');
      if (tbAppr) {
        tbAppr.textContent = overview.pending_approvals + ' approvals pending';
        tbAppr.className = 'tb-counter' + (overview.pending_approvals > 0 ? ' tb-warn' : '');
      }
      var aiPill = document.getElementById('pill-ai');
      if (aiPill) {
        var aiProvider = overview.ai_provider || 'disabled';
        var aiLabel = aiProvider === 'mock' ? 'MOCK (ADVISORY)'
          : (aiProvider === 'openai-compatible' ? 'LIVE (ADVISORY)' : 'DISABLED');
        aiPill.textContent = 'AI: ' + aiLabel;
        aiPill.className = 'pill' + (aiProvider !== 'disabled' ? ' pill-ok' : '');
      }
      renderSeverityBars(overview);
    });
  }

  // ------------------------------------------------------------------
  // Alert queue + detail
  // ------------------------------------------------------------------

  function severityChip(alert) {
    return el('span', 'chip ' + (severityClasses[alert.severity] || 'unknown'),
      alert.severity || '?');
  }

  function stateChip(state) {
    var cls = state === 'ok' || state === 'SUCCEEDED' || state === 'approved' ? 'chip-ok' : '';
    if (state === 'RUNNING' || state === 'APPROVED') cls = 'chip-run';
    if (state === 'WAITING_APPROVAL' || state === 'PENDING' || state === 'pending') cls = 'chip-wait';
    if (state === 'VALIDATION_FAILED' || state === 'rejected' || state === 'expired'
      || state === 'ACTION_FAILED' || state === 'TIMED_OUT') cls = 'chip-bad';
    return el('span', 'chip ' + cls, state || '?');
  }

  function queueCell(text, className) {
    return el('td', className, text == null ? '—' : text);
  }

  function buildAlertRow(alert) {
    var row = el('tr', 'queue-row');
    row.appendChild(queueCell('#' + alert.id, 'queue-strong'));
    row.appendChild(queueCell(alert.time));
    row.appendChild(queueCell(alert.rule + (alert.rule_id ? ' (' + alert.rule_id + ')' : '')));
    row.appendChild(queueCell(alert.attack_category));
    var source = alert.source_ips && alert.source_ips.length ?
      alert.source_ips.join(', ') : null;
    row.appendChild(queueCell(source));
    var target = (alert.affected_users && alert.affected_users.length ?
      alert.affected_users.join(', ') : null) ||
      (alert.hostnames && alert.hostnames.length ? alert.hostnames.join(', ') : null);
    row.appendChild(queueCell(target));
    row.appendChild(queueCell(null)).appendChild(severityChip(alert));
    row.appendChild(queueCell(alert.deterministic_risk_score == null ?
      '—' : alert.deterministic_risk_score + '/100'));
    row.appendChild(queueCell(alert.jev_priority));
    row.appendChild(queueCell(alert.ai_status === 'ok' ? 'AI done' : null,
      alert.ai_status === 'ok' ? 'queue-ai-ok' : null));
    row.appendChild(queueCell(alert.investigation_status));
    row.appendChild(queueCell((alert.incident_ids && alert.incident_ids.length) ?
      alert.incident_ids.join(', ') : null));
    row.addEventListener('click', function () {
      openAlertDetail(alert.id);
    });
    // Full detail text stays a text node (XSS-safe) as a second line in the
    // rule cell.
    var ruleCell = row.cells[2];
    var details = document.createElement('div');
    details.className = 'queue-details';
    details.textContent = alert.details;
    ruleCell.appendChild(details);
    return row;
  }

  var latestAlerts = [];

  function fetchAlerts() {
    return fetchJSON('/api/soc/alerts').then(function (alerts) {
      var list = Array.isArray(alerts) ? alerts : [];
      latestAlerts = list;
      var filter = filterSel.value;
      var shown = list.filter(function (alert) {
        return filter === 'all' || alert.severity === filter;
      });
      var tbody = document.getElementById('alert-queue');
      tbody.replaceChildren.apply(tbody,
        shown.length ? shown.map(buildAlertRow) : [emptyQueueRow()]);
      lastUpdate.textContent = 'Updated ' + new Date().toLocaleTimeString();
      var totalNode = document.getElementById('soc-total');
      if (totalNode) totalNode.textContent = String(list.length);
      renderMitreBars(list);
      renderSourceBars(list);
      // Jev pill reflects the actual stored decision status of the newest alert.
      var jevStatus = list.length ? (list[0].jev_status || '') : '';
      if (jevStatus === 'fallback') {
        setPill('pill-jev', 'JEV: FALLBACK (DETERMINISTIC)', 'pill-warn');
      } else if (jevStatus) {
        setPill('pill-jev', 'JEV: ACTIVE', 'pill-ok');
      } else {
        setPill('pill-jev', 'JEV: STANDBY', '');
      }
    }).catch(function () {
      lastUpdate.textContent = 'Unable to load alerts. Check the local service.';
    });
  }

  function emptyQueueRow() {
    var row = el('tr');
    var cell = el('td', 'meta', 'No alerts yet — generate a scenario in the Simulation Lab below.');
    cell.colSpan = 12;
    row.appendChild(cell);
    return row;
  }

  // ------------------------------------------------------------------
  // Alert detail (consolidated analyst view)
  // /api/soc/alerts/<id>/full
  // ------------------------------------------------------------------

  function openAlertDetail(alertId) {
    currentAlertId = alertId;
    var panel = document.getElementById('alert-detail');
    panel.hidden = false;
    panel.replaceChildren(line('Loading alert #' + alertId + ' …'));
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    fetchJSON('/api/soc/alerts/' + encodeURIComponent(alertId) + '/full')
      .then(function (full) {
        renderAlertDetail(panel, full);
        // WHY panel + decision chain + analyst case come from the stored
        // decision endpoint (no AI engine call).
        return fetchJSON('/api/alerts/' + encodeURIComponent(alertId)
          + '/decision').then(function (decision) {
          if (currentAlertId !== alertId) return null;
          var why = el('div', 'why-region');
          panel.insertBefore(why, panel.firstChild.nextSibling);
          renderWhyPanel(why, decision);
          renderDecisionChain(why, decision);
          var caseWrap = el('div', 'case-region');
          panel.appendChild(caseWrap);
          renderCasePanel(caseWrap, { id: alertId }, decision);
          return null;
        });
      })
      .catch(function (error) {
        panel.replaceChildren(line('Unable to load alert detail: ' + error.message,
          'meta soar-err'));
      });
  }

  function closeDetail() {
    currentAlertId = null;
    var panel = document.getElementById('alert-detail');
    panel.hidden = true;
    panel.replaceChildren();
  }

  function renderAlertDetail(panel, full) {
    var alert = full.alert || {};
    var soar = full.soar || {};
    var ai = full.ai || {};
    var investigation = full.investigation;
    panel.replaceChildren();

    var card = el('div', 'detail-head');
    card.className = 'alert ' + (severityClasses[alert.severity] || 'unknown')
      + ' detail-head';
    var title = el('div', 'detail-title');
    title.appendChild(severityChip(alert));
    title.appendChild(el('span', 'detail-name',
      ' Alert #' + alert.id + ' — ' + alert.rule + ' (' + (alert.rule_id || '?') + ')'));
    var close = el('button', 'detail-close', 'Close');
    close.type = 'button';
    close.addEventListener('click', closeDetail);
    var closeWrap = el('span', 'detail-close-wrap');
    closeWrap.appendChild(close);
    title.appendChild(closeWrap);
    card.appendChild(title);
    addLines(card, [
      line('Time: ' + alert.time + '  ·  Details: ' + alert.details),
      line('Risk: ' + (alert.deterministic_risk_score == null ? 'unavailable' :
        alert.deterministic_risk_score + '/100 (' + (alert.risk_band || '?') + ')')
        + (alert.risk_explanation ? ' — ' + alert.risk_explanation : '')),
      line('Correlation: ' + (alert.correlation_id || '—') + '  ·  Investigation status: '
        + (alert.investigation_status || '—')),
      line('Entities: sources ' + ((alert.source_ips || []).join(', ') || '—')
        + ' · users ' + ((alert.affected_users || []).join(', ') || '—')
        + ' · hosts ' + ((alert.hostnames || []).join(', ') || '—')
        + ' · processes ' + ((alert.processes || []).join(', ') || '—')),
      intelLine(alert),
    ]);
    panel.appendChild(card);
    if (currentAlertId !== alert.id) return;

    // -- deterministic investigation + evidence (existing Phase 3 engine) --
    if (investigation) {
      var invPanel = el('div', 'investigation');
      panel.appendChild(invPanel);
      var invHead = addSection(invPanel, 'Investigation — deterministic evidence');
      addLines(invHead, [
        line('Timeline (' + ((investigation.timeline || {}).total_events || 0) + ' events):'),
      ]);
      var tl = (investigation.timeline || {}).entries || [];
      tl.slice(0, 8).forEach(function (entry) {
        invHead.appendChild(line('  ' + (entry.timestamp || '?') + ' — '
          + (entry.event_type || '?')
          + (entry.src_ip ? ' — ' + entry.src_ip : '')
          + (entry.user ? ' — ' + entry.user : '')));
      });
      var mitigation = addSection(invPanel, 'Correlation / related alerts / intel');
      addLines(mitigation, [
        line('Related alerts: ' + ((((investigation.related_alerts || {}).alerts) || [])
          .map(function (rel) { return '#' + rel.alert_id + ' ' + rel.rule; })
          .join(', ') || 'none')),
        line('Threat intel: ' + ((((investigation.threat_intel || {}).matches) || [])
          .map(function (match) {
            if (match.fields) {
              return 'stored enrichment ' + Object.keys(match.fields)
                .map(function (key) { return key + '=' + match.fields[key]; }).join(', ');
            }
            return (match.known_malicious ? 'KNOWN ' : 'unknown ') + match.indicator_type
              + ' ' + match.indicator;
          }).join(', ') || 'no stored intel match')),
        line('MITRE ATT&CK (deterministic): ' + ((((investigation.mitre || {}).techniques) || [])
          .map(function (tech) { return tech.technique_id; }).join(', ') || 'none')),
        line('Investigation status transitions: ' + alert.investigation_status),
      ]);
      var questions = addSection(invPanel, 'Investigation questions');
      addLines(questions, textLines(investigation.investigation_questions || []));
      var askBody = addSection(invPanel, 'Ask about this alert (evidence-bounded)');
      var askInput = el('input');
      askInput.type = 'text';
      askInput.maxLength = 256;
      askInput.placeholder = 'Has this source IP attacked other accounts?';
      askInput.className = 'ask-input';
      var askBtn = el('button', '', 'Ask');
      askBtn.type = 'button';
      var askOut = el('div', 'ask-output');
      askBtn.addEventListener('click', function () {
        var question = askInput.value.trim();
        if (!question) return;
        askOut.replaceChildren(line('Checking stored evidence …'));
        fetchJSON('/api/alerts/' + alert.id + '/ai-question', {
          method: 'POST', headers: authHeaders(),
          body: JSON.stringify({ question: question }),
        }).then(function (answer) {
          askOut.replaceChildren(
            line('Answer: ' + answer.answer, 'ask-ans'),
            line('Basis: ' + (answer.basis || []).join(' | '), 'meta'));
        }).catch(function (error) {
          askOut.replaceChildren(line('Question failed: ' + error.message, 'meta soar-err'));
        });
      });
      askBody.appendChild(askInput);
      askBody.appendChild(askBtn);
      askBody.appendChild(askOut);
    }

    // -- advisory AI panel (labeled AI-GENERATED / ADVISORY) --------------
    var aiPanel = addSection(panel, 'THREATWATCH AI ANALYST — AI-GENERATED / ADVISORY',
      'ai-advisory');
    if (!ai || ai.status !== 'ok') {
      addLines(aiPanel, [
        line('AI status: ' + ((ai && ai.status) || 'unavailable')
          + (ai && ai.reason ? ' (' + ai.reason + ')' : '')),
        line('AI status: unavailable — configure AI to enable the advisory analyst.',
          'meta'),
      ]);
    } else {
      var response = ai.response || {};
      var model = (ai.model || {}).model || 'unknown model';
      addLines(aiPanel, [
        line('AI status: ok (model ' + model + ') — advisory only, can be wrong'),
        line('Summary: ' + (response.summary || '(none)')),
        line('Assessment: ' + (response.assessment || '(none)')),
        line('AI priority: ' + (response.priority || 'unknown')
          + ' | malicious likelihood: ' + fmtLik(response.malicious_likelihood)
          + ' | false-positive likelihood: ' + fmtLik(response.false_positive_likelihood)
          + ' | confidence: ' + fmtLik(response.confidence)),
        (ai.jev_context && ai.jev_context.priority)
          ? line('Jev decision (deterministic, not AI): ' + ai.jev_context.priority)
          : line('Jev decision (deterministic, not AI): unavailable'),
      ]);
      addLines(aiPanel, (response.key_evidence || []).slice(0, 8).map(function (item, i) {
        return line('Key evidence ' + (i + 1) + ': ' + item);
      }));
      addLines(aiPanel, (response.mitre_assessment || []).slice(0, 8).map(function (entry) {
        return line('ATT&CK ' + entry.technique_id + ': ' + entry.relevance
          + (entry.rationale ? ' — ' + entry.rationale : ''));
      }));
      addLines(aiPanel, (response.recommended_actions || []).slice(0, 8).map(function (action, i) {
        return line('Recommended step ' + (i + 1) + ': ' + (action.action || '')
          + (action.reason ? ' — ' + action.reason : ''));
      }));
      if (response.source_references && response.source_references.length) {
        addLines(aiPanel, response.source_references.slice(0, 10).map(function (reference) {
          return line('Source (' + reference.type + '): ' + reference.value);
        }));
      } else {
        addLines(aiPanel, [line('Sources: none cited by the model for this assessment')]);
      }
      var askAi = el('button', '', 'Run AI investigation');
      askAi.type = 'button';
      askAi.addEventListener('click', function () {
        runAiInvestigation(alert.id, aiPanel);
      });
      aiPanel.appendChild(askAi);
    }
    if (currentAlertId !== alert.id) return;

    // -- SOAR section: playbook suggestion, executions, approvals, audit --
    // Wrapped in a .soar-region so refreshDetailSoar() can keep the open
    // detail live (executions/approvals/audit) without re-rendering the
    // whole panel or re-running the AI engine.
    var soarRegion = el('div', 'soar-region');
    panel.appendChild(soarRegion);
    buildSoarRegion(soarRegion, alert, soar);
  }

  function buildSoarRegion(container, alert, soar) {
    container.replaceChildren();
    // Transient action feedback lives here so refreshDetailSoar() can
    // rebuild the region without erasing it.
    var status = el('div', 'soar-status');
    container.appendChild(status);
    var soarPanel = addSection(container, 'SOAR — playbook workflow');
    addLines(soarPanel, [line('Matched playbooks: '
      + ((soar.matched_playbooks || []).join(', ') || 'none'))]);
    if (soar.playbook) {
      var def = (soar.playbook.definition || {});
      addLines(soarPanel, [
        line('Suggested playbook: ' + soar.playbook.playbook_id + ' v'
          + soar.playbook.version + ' — ' + soar.playbook.name
          + ' (approval policy: ' + def.approval_policy + ', failure policy: '
          + def.failure_policy + ')'),
      ]);
      (def.actions || []).forEach(function (action, index) {
        soarPanel.appendChild(line('  ' + (index + 1) + '. ' + action.type
          + (action.requires_approval ? '  [requires approval]' : '')
          + (action.parameters && action.parameters.note ?
            '  — ' + action.parameters.note : '')));
      });
      if (soar.recommendation) {
        var rec = soar.recommendation;
        addLines(soarPanel, [
          line('Dry-run preview execution: ' + rec.execution_id + ' — state '
            + rec.state + ' (DRY RUN — no external effect)'),
        ]);
      }
      var executeBtn = el('button', 'soar-btn', 'Execute playbook (dry-run by default)');
      executeBtn.type = 'button';
      executeBtn.addEventListener('click', function () {
        executePlaybook(soar.playbook.playbook_id, alert.id, status);
      });
      soarPanel.appendChild(executeBtn);
    }
    (soar.executions || []).forEach(function (execution) {
      var row = el('div', 'soar-item');
      row.appendChild(stateChip(execution.state));
      row.appendChild(line(execution.execution_id + ' — ' + execution.playbook_id
        + ' v' + execution.playbook_version + ' · '
        + (execution.dry_run ? 'DRY RUN' : 'REAL EXECUTION')));
      (execution.actions || []).forEach(function (action) {
        row.appendChild(line('  action[' + action.action_index + '] ' + action.action_type
          + ': ' + action.state + (action.result && action.result.dry_run !== undefined
            ? '' : '') + (action.error ? ' — ' + action.error : ''),
            'meta soar-action'));
      });
      soarPanel.appendChild(row);
    });
    (soar.approvals || []).forEach(function (approval) {
      var row = el('div', 'soar-item');
      row.appendChild(stateChip(approval.decision));
      row.appendChild(line(approval.approval_id + ' — ' + approval.action_type
        + ' (role: ' + approval.required_role + ', expires ' + approval.expires_at + ')'));
      if (approval.decision === 'pending') {
        var approve = el('button', 'soar-btn', 'Approve');
        var reject = el('button', 'soar-btn soar-btn-bad', 'Reject');
        approve.type = 'button';
        reject.type = 'button';
        approve.addEventListener('click', function () {
          decideApproval(approval.approval_id, 'approve', status);
        });
        reject.addEventListener('click', function () {
          decideApproval(approval.approval_id, 'reject', status);
        });
        row.appendChild(approve);
        row.appendChild(reject);
      }
      soarPanel.appendChild(row);
    });
    var auditBody = addSection(container, 'SOC audit trail');
    var auditRows = soar.audit || [];
    if (!auditRows.length) {
      addLines(auditBody, [line('No audit entries for this alert yet.')]);
    }
    auditRows.slice(0, 30).forEach(function (entry) {
      auditBody.appendChild(buildAuditEntry(entry));
    });
  }

  function refreshDetailSoar() {
    if (currentAlertId === null) return;
    var panel = document.getElementById('alert-detail');
    var region = panel.querySelector('.soar-region');
    if (!region) return;
    var alertId = currentAlertId;
    fetchJSON('/api/soc/alerts/' + encodeURIComponent(alertId) + '/soar')
      .then(function (data) {
        if (currentAlertId !== alertId) return;
        // Carry over recent action messages so a live rebuild never erases
        // the feedback the analyst just received.
        var previousStatus = region.querySelector('.soar-status');
        var preserved = previousStatus
          ? Array.prototype.slice.call(previousStatus.childNodes).slice(-5)
          : [];
        buildSoarRegion(region, data.alert || {}, data.soar || {});
        if (preserved.length) {
          var newStatus = region.querySelector('.soar-status');
          if (newStatus) {
            preserved.forEach(function (node) { newStatus.appendChild(node); });
          }
        }
      })
      .catch(function () { /* transient polling error — keep last state */ });
  }

  function intelLine(alert) {
    if (!alert.intel || !alert.intel.length) {
      return line('Intel: no stored enrichment rows');
    }
    return line('Intel: ' + alert.intel.map(function (item) {
      return item.key + '=' + item.value;
    }).join(', '));
  }

  function fmtLik(value) {
    return (value === null || value === undefined) ? '?' : String(value);
  }

  function runAiInvestigation(alertId, container) {
    var status = line('Running AI investigation (uses the mock/offline provider by default) …');
    container.appendChild(status);
    fetchJSON('/api/alerts/' + alertId + '/ai-investigation', {
      method: 'POST', headers: authHeaders(),
    }).then(function (ai) {
      status.remove();
      if (!ai || ai.status !== 'ok') {
        container.appendChild(line('AI status: ' + ((ai && ai.status) || 'unavailable')
          + (ai && ai.reason ? ' (' + ai.reason + ')' : ''), 'meta soar-err'));
        return;
      }
      container.appendChild(line('AI investigation refreshed — reload the alert detail to '
        + 'see the persisted result in the AI ANALYST panel.'));
      container.appendChild(line('Summary: ' + ((ai.response || {}).summary || '(none)')));
    }).catch(function (error) {
      status.remove();
      container.appendChild(line('AI investigation failed: ' + error.message,
        'meta soar-err'));
    });
  }

  function executePlaybook(playbookId, alertId, container) {
    var status = line('Requesting dry-run execution …');
    container.appendChild(status);
    fetchJSON('/api/playbooks/' + encodeURIComponent(playbookId) + '/execute', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ alert_id: alertId, dry_run: true, actor: 'analyst' }),
    }).then(function (execution) {
      status.remove();
      container.appendChild(line('Execution ' + execution.execution_id + ' queued: '
        + execution.state + (execution.dry_run ? ' (DRY RUN)' : ' (REAL)')));
      // Drive the execution to its first stop (validation or the approval
      // gate). advance() can never bypass a human approval.
      return fetchJSON('/api/soar/executions/'
        + encodeURIComponent(execution.execution_id) + '/advance', {
        method: 'POST', headers: authHeaders(),
        body: JSON.stringify({ actor: 'analyst' }),
      }).then(function (advanced) {
        container.appendChild(line('Advanced to ' + advanced.state
          + (advanced.state === 'WAITING_APPROVAL'
            ? ' — human approval required below.' : '.'), 'ask-ans'));
        refreshAll();
        refreshDetailSoar();
        return null;
      });
    }).catch(function (error) {
      status.remove();
      var duplicate = error.message.indexOf('duplicate_execution') !== -1
        || error.message.indexOf('already exists') !== -1;
      if (duplicate) {
        var existing = (error.message.match(/EXE-[A-F0-9]+/) || [])[0];
        container.appendChild(line('This playbook already ran for this alert '
          + '(idempotency) — advancing the existing execution instead.', 'meta'));
        if (existing) {
          fetchJSON('/api/soar/executions/' + encodeURIComponent(existing)
            + '/advance', {
            method: 'POST', headers: authHeaders(),
            body: JSON.stringify({ actor: 'analyst' }),
          }).then(function (advanced) {
            container.appendChild(line('Execution ' + existing + ' advanced to '
              + advanced.state + (advanced.state === 'WAITING_APPROVAL'
                ? ' — human approval required below.' : '.'), 'ask-ans'));
            refreshAll();
            refreshDetailSoar();
            return null;
          }).catch(function (advanceError) {
            container.appendChild(line('Advance failed: ' + advanceError.message,
              'meta soar-err'));
          });
        }
        return;
      }
      container.appendChild(line('Execution failed: ' + error.message, 'meta soar-err'));
    });
  }

  function decideApproval(approvalId, decision, row) {
    fetchJSON('/api/soar/approvals/' + encodeURIComponent(approvalId) + '/' + decision, {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ approver: 'analyst' }),
    }).then(function (execution) {
      row.appendChild(line('Approval ' + decision + ': execution is now '
        + execution.state, 'ask-ans'));
      refreshAll();
      refreshDetailSoar();
    }).catch(function (error) {
      row.appendChild(line('Approval failed: ' + error.message, 'meta soar-err'));
    });
  }

  // ------------------------------------------------------------------
  // Simulation lab
  // ------------------------------------------------------------------

  function loadScenarioCatalog() {
    return fetchJSON('/api/simulation/scenarios').then(function (data) {
      var select = document.getElementById('sim-scenario');
      var rows = data.scenarios || [];
      var options = rows.map(function (scenario) {
        var option = document.createElement('option');
        option.value = scenario.scenario_id;
        option.textContent = scenario.name
          + (scenario.classification === 'benign' ? ' (benign)' : '');
        return option;
      });
      select.replaceChildren.apply(select, options);
      if (rows.length) {
        select.value = rows[0].scenario_id;
        showScenarioDescription(rows[0]);
      }
      select.addEventListener('change', function () {
        var match = rows.filter(function (scenario) {
          return scenario.scenario_id === select.value;
        })[0];
        showScenarioDescription(match);
      });
    });
  }

  function showScenarioDescription(scenario) {
    var body = document.getElementById('sim-desc');
    if (!scenario) { body.textContent = ''; return; }
    body.textContent = scenario.description
      + ' — expected: '
      + (scenario.expected.rule_id ? scenario.expected.rule_id + ' / ' : '')
      + (scenario.expected.severity ? scenario.expected.severity : 'no alert')
      + (scenario.expected.mitre && scenario.expected.mitre.length ?
        ' / MITRE ' + scenario.expected.mitre.join(', ') : '')
      + ' [' + scenario.classification + ']';
  }

  // ------------------------------------------------------------------
  // Attack Replay: event-by-event through the real pipeline
  // ------------------------------------------------------------------

  var currentReplayId = null;

  function startReplay() {
    var out = document.getElementById('replay-progress');
    var headers = authHeaders();
    if (!headers.Authorization) {
      out.replaceChildren(line('Enter the console token above to start a replay '
        + '(protected action).', 'meta soar-err'));
      return;
    }
    if (!currentRunId) {
      out.replaceChildren(line('Generate a scenario in the Simulation Lab first, '
        + 'then replay it here.', 'meta'));
      return;
    }
    var delay = document.getElementById('replay-delay').value || '400';
    out.replaceChildren(line('Starting SYNTHETIC / LAB replay of run '
      + currentRunId + ' …'));
    fetchJSON('/api/simulation/replay', {
      method: 'POST', headers: headers,
      body: JSON.stringify({ run_id: currentRunId,
        step_delay_ms: parseInt(delay, 10) }),
    }).then(function (replay) {
      currentReplayId = replay.replay_id;
      renderReplayProgress(replay);
      stepReplay();
      return null;
    }).catch(function (error) {
      out.replaceChildren(line('Replay failed to start: ' + error.message,
        'meta soar-err'));
    });
  }

  function stepReplay() {
    if (!currentReplayId) return;
    fetchJSON('/api/simulation/replays/'
      + encodeURIComponent(currentReplayId) + '/step', {
      method: 'POST', headers: authHeaders(),
    }).then(function (data) {
      renderReplayProgress(data.replay);
      if (data.step) appendReplayStep(data.step, data.replay);
      var done = data.replay.status === 'complete';
      if (!done) {
        var delay = parseInt(
          document.getElementById('replay-delay').value || '400', 10);
        setTimeout(stepReplay, delay);
      } else {
        refreshAll();
      }
      return null;
    }).catch(function (error) {
      document.getElementById('replay-progress').replaceChildren(
        line('Replay step failed: ' + error.message, 'meta soar-err'));
    });
  }

  function renderReplayProgress(replay) {
    var out = document.getElementById('replay-progress');
    var pct = replay.total_events
      ? Math.round(100 * replay.processed_events / replay.total_events) : 0;
    out.replaceChildren(line('SYNTHETIC / LAB — replay ' + replay.replay_id
      + ' — scenario ' + replay.scenario_id + ' — event '
      + replay.processed_events + '/' + replay.total_events
      + ' (' + pct + '%) — status ' + replay.status.toUpperCase()));
  }

  function appendReplayStep(step, replay) {
    var container = document.getElementById('replay-steps');
    var row = el('div', 'replay-step'
      + (step.alert_ids.length ? ' replay-step-alert' : ''));
    row.appendChild(line('#' + (step.event_index + 1) + '  '
      + step.event_id + (step.accepted ? '  accepted' : '  duplicate'),
      'meta'));
    if (step.alert_ids.length) {
      row.appendChild(line('⚠ DETECTION TRIGGERED — alert #'
        + step.alert_ids.join(', #')
        + ' — opening the alert shows the full WHY panel', 'ask-ans'));
    }
    container.appendChild(row);
    if (container.children.length > 130) container.removeChild(container.firstChild);
  }

  function resetReplay() {
    currentReplayId = null;
    document.getElementById('replay-progress').replaceChildren(
      line('Replay cleared. Generate a scenario and press START REPLAY.', 'meta'));
    document.getElementById('replay-steps').replaceChildren();
  }

  // ------------------------------------------------------------------
  // WHY THREATWATCH ALERTED panel + decision chain (alert detail)
  // ------------------------------------------------------------------

  function chipFor(value, kind) {
    var cls = 'chip';
    if (kind === 'bad' || value === 'HIGH' || value === 'CRITICAL'
      || value === 'confirmed_threat' || value === 'SUCCEEDED') cls += ' chip-bad';
    else if (kind === 'warn' || value === 'MEDIUM' || value === 'investigating'
      || value === 'WAITING_APPROVAL' || value === 'RUNNING' || value === 'PENDING'
      || value === 'pending') cls += ' chip-warn';
    else if (kind === 'info' || value === 'LOW' || value === 'false_positive'
      || value === 'closed') cls += ' chip-info';
    else if (kind === 'ok') cls += ' chip-ok';
    return el('span', cls, value || '—');
  }

  function renderDecisionChain(panel, decision) {
    var wrap = addSection(panel, 'DECISION CHAIN — DETECTION TO RESPONSE');
    var chain = el('div', 'decision-chain');
    var jevStatus = (decision.jev || {}).status || 'not_recorded';
    var aiStatus = (decision.ai || {}).status || 'not_run';
    var caseState = decision.case ? decision.case.status : 'no case';
    var execs = (decision.soar || {}).executions || [];
    var execState = execs.length ? execs[0].state : 'not started';
    var stages = [
      ['EVENTS', decision.detection.matched_events + ' ingested'],
      ['DETECTION', (decision.detection.rule_id || decision.detection.rule)
        + ' fired'],
      ['EVIDENCE', decision.detection.source_event_ids.length
        + ' linked events'],
      ['RISK', (decision.risk.score == null ? '—' : decision.risk.score + '/100 '
        + (decision.risk.band || ''))],
      ['JEV', jevStatus + (decision.jev.priority
        ? ' · ' + decision.jev.priority : '')],
      ['AI / RAG', aiStatus + (aiStatus === 'disabled' ? ' (deterministic only)'
        : aiStatus === 'ok' ? ' (advisory)' : '')],
      ['INCIDENT', decision.case ? 'case ' + decision.case.case_id
        : (decision.incident_ids.length ? 'incident created' : 'not created')],
      ['ANALYST', caseState.toUpperCase()],
      ['SOAR', execState + (execs.length && execs[0].dry_run
        ? ' (dry run)' : '')],
    ];
    stages.forEach(function (stage, index) {
      var node = el('div', 'chain-node');
      node.appendChild(el('span', 'chain-stage', stage[0]));
      node.appendChild(el('span', 'chain-state', stage[1]));
      chain.appendChild(node);
      if (index < stages.length - 1) {
        chain.appendChild(el('span', 'chain-arrow', '↓'));
      }
    });
    wrap.appendChild(chain);
  }

  function renderWhyPanel(panel, decision) {
    var wrap = addSection(panel, 'WHY THREATWATCH ALERTED');
    var identity = decision.identity;
    var detection = decision.detection;

    var head = el('div', 'why-grid');
    head.appendChild(el('div', 'why-label', 'DETECTION'));
    head.appendChild(el('div', 'why-value',
      (detection.rule_id || '—') + ' ' + (detection.rule || '')));

    head.appendChild(el('div', 'why-label', 'EVIDENCE'));
    var evidence = el('div', 'why-value');
    evidence.appendChild(line('✓ ' + detection.matched_events
      + ' matching event(s) linked to this alert'));
    evidence.appendChild(line('✓ Source IP: '
      + (identity.source_ips.join(', ') || 'none observed')));
    if (identity.affected_users.length) {
      evidence.appendChild(line('✓ Affected user(s): '
        + identity.affected_users.join(', ')));
    }
    if (identity.hostnames.length) {
      evidence.appendChild(line('✓ Affected host(s): '
        + identity.hostnames.join(', ')));
    }
    if (detection.correlation_id) {
      evidence.appendChild(line('✓ Correlation group: '
        + detection.correlation_id));
    }
    head.appendChild(evidence);

    head.appendChild(el('div', 'why-label', 'RISK CALCULATION'));
    var riskBox = el('div', 'why-value why-risk');
    var factors = decision.risk.factors || {};
    Object.keys(factors).forEach(function (name) {
      var row = el('div', 'risk-factor-row');
      row.appendChild(el('span', 'risk-factor-name', name.replace(/_/g, ' ')));
      row.appendChild(el('span', 'risk-factor-pts',
        '+' + factors[name]));
      riskBox.appendChild(row);
    });
    var totalRow = el('div', 'risk-factor-row risk-total');
    totalRow.appendChild(el('span', 'risk-factor-name',
      'RISK SCORE'));
    totalRow.appendChild(el('span', 'risk-factor-pts',
      (decision.risk.score == null ? '—' : decision.risk.score + '/100')
      + ' (' + (decision.risk.band || '—') + ')'));
    riskBox.appendChild(totalRow);
    if (decision.risk.explanation) {
      riskBox.appendChild(line(decision.risk.explanation, 'meta'));
    }
    head.appendChild(riskBox);

    head.appendChild(el('div', 'why-label', 'CLASSIFICATION'));
    var sevBox = el('div', 'why-value');
    sevBox.appendChild(chipFor(identity.severity, 'sev'));
    head.appendChild(sevBox);

    head.appendChild(el('div', 'why-label', 'MITRE ATT&CK'));
    head.appendChild(el('div', 'why-value',
      (decision.mitre.techniques.join(', ') || 'none recorded')));

    head.appendChild(el('div', 'why-label', 'JEV (DETERMINISTIC)'));
    var jevBox = el('div', 'why-value');
    jevBox.appendChild(chipFor((decision.jev.priority
      || 'no decision').toUpperCase(), 'warn'));
    jevBox.appendChild(line('provider/state: ' + decision.jev.status
      + ' — Jev output is deterministic, never AI-generated', 'meta'));
    head.appendChild(jevBox);

    head.appendChild(el('div', 'why-label', 'AI'));
    var aiBox = el('div', 'why-value');
    var aiStatus = decision.ai.status || 'not_run';
    var aiLabel = aiStatus === 'ok' ? 'ADVISORY (stored AI result)'
      : aiStatus === 'not_run' ? 'NOT RUN — provider: '
        + (decision.ai.provider || 'configured') + ' (advisory only)'
      : aiStatus === 'disabled' ? 'DISABLED (deterministic engine only)'
      : aiStatus.toUpperCase();
    aiBox.appendChild(chipFor('AI: ' + aiLabel,
      aiStatus === 'ok' ? 'warn' : 'info'));
    if (decision.ai.summary) {
      aiBox.appendChild(line('Summary: ' + decision.ai.summary, 'meta'));
    }
    if (decision.ai.reason) {
      aiBox.appendChild(line('Status reason: ' + decision.ai.reason, 'meta'));
    }
    head.appendChild(aiBox);

    head.appendChild(el('div', 'why-label', 'FINAL STATE'));
    var finalBox = el('div', 'why-value');
    finalBox.appendChild(chipFor(
      decision.case ? decision.case.status.toUpperCase()
        : (decision.incident_ids.length ? 'INCIDENT OPEN'
          : 'ALERT OPEN — NO CASE'),
      decision.case && decision.case.status === 'confirmed_threat'
        ? 'bad' : 'info'));
    head.appendChild(finalBox);

    wrap.appendChild(head);
  }

  // ------------------------------------------------------------------
  // Analyst case workflow (inside alert detail)
  // ------------------------------------------------------------------

  function renderCasePanel(panel, alert, decision) {
    var wrap = addSection(panel, 'ANALYST CASE — DECISION WORKFLOW');
    var body = el('div', 'case-body');
    wrap.appendChild(body);
    // drawCasePanel reads decision.case itself (same payload reloadDecision
    // passes back), so an existing case renders on first detail open too.
    drawCasePanel(body, alert, decision);
  }

  function drawCasePanel(container, alert, decision) {
    container.replaceChildren();
    var caseInfo = decision && decision.case;
    if (!caseInfo) {
      var startBtn = el('button', 'soar-btn', 'Start investigation (open case)');
      startBtn.type = 'button';
      startBtn.addEventListener('click', function () {
        openCaseForAlert(alert.id, container, decision);
      });
      container.appendChild(line('No analyst case yet for this alert.', 'meta'));
      container.appendChild(startBtn);
      return;
    }
    container.appendChild(line('Case ' + caseInfo.case_id
      + ' — incident ' + caseInfo.incident_id + ' — analyst '
      + caseInfo.analyst, 'meta'));
    var stateRow = el('div', 'case-states');
    var states = ['NEW', 'INVESTIGATING', decision.case.decision === 'false_positive'
      ? 'FALSE POSITIVE' : 'CONFIRMED THREAT', 'CLOSED'];
    var order = ['new', 'investigating', decision.case.decision
      === 'false_positive' ? 'false_positive' : 'confirmed_threat', 'closed'];
    var activeIdx = order.indexOf(caseInfo.status);
    states.forEach(function (label, index) {
      var node = el('span', 'case-state'
        + (index === activeIdx ? ' case-state-active'
          : (index < activeIdx ? ' case-state-done' : '')), label);
      stateRow.appendChild(node);
      if (index < states.length - 1) {
        stateRow.appendChild(el('span', 'chain-arrow', '→'));
      }
    });
    container.appendChild(stateRow);

    var noteInput = el('input', 'ask-input');
    noteInput.type = 'text';
    noteInput.maxLength = 2000;
    noteInput.placeholder = 'Analyst note (required for confirm/false-positive)…';
    var noteBtn = el('button', 'soar-btn', 'Add note');
    noteBtn.type = 'button';
    noteBtn.addEventListener('click', function () {
      if (!noteInput.value.trim()) return;
      fetchJSON('/api/cases/' + encodeURIComponent(caseInfo.case_id)
        + '/notes', {
        method: 'POST', headers: authHeaders(),
        body: JSON.stringify({ note: noteInput.value.trim() }),
      }).then(function () {
        noteInput.value = '';
        reloadDecision(alert.id, container, decision);
        return null;
      }).catch(function (error) {
        container.appendChild(line('Note failed: ' + error.message,
          'meta soar-err'));
      });
    });
    container.appendChild(noteInput);
    container.appendChild(noteBtn);

    var actions = el('div', 'case-actions');
    function transitionButton(label, toState, needsNote) {
      var btn = el('button', 'soar-btn'
        + (toState === 'false_positive' ? ' soar-btn-bad' : ''), label);
      btn.type = 'button';
      btn.addEventListener('click', function () {
        var note = noteInput.value.trim();
        if (needsNote && !note) {
          container.appendChild(line('A note is required to mark this case '
            + to_state + '.', 'meta soar-err'));
          return;
        }
        var payload = { to_state: toState };
        if (note) payload.note = note;
        fetchJSON('/api/cases/' + encodeURIComponent(caseInfo.case_id)
          + '/transition', {
          method: 'POST', headers: authHeaders(),
          body: JSON.stringify(payload),
        }).then(function () {
          noteInput.value = '';
          reloadDecision(alert.id, container, decision);
          return null;
        }).catch(function (error) {
          container.appendChild(line('Transition failed: ' + error.message,
            'meta soar-err'));
        });
      });
      actions.appendChild(btn);
    }
    if (caseInfo.status === 'new') {
      transitionButton('Begin investigating', 'investigating', false);
      transitionButton('Confirm threat', 'confirmed_threat', true);
      transitionButton('Mark false positive', 'false_positive', true);
    } else if (caseInfo.status === 'investigating') {
      transitionButton('Confirm threat', 'confirmed_threat', true);
      transitionButton('Mark false positive', 'false_positive', true);
      transitionButton('Close case', 'closed', false);
    } else if (caseInfo.status === 'confirmed_threat'
      || caseInfo.status === 'false_positive') {
      transitionButton('Close case', 'closed', false);
      transitionButton('Reopen (investigating)', 'investigating', false);
    }
    container.appendChild(actions);

    if (caseInfo.decision) {
      container.appendChild(line('Analyst decision: '
        + caseInfo.decision.toUpperCase(), 'ask-ans'));
    }
    var notes = caseInfo.notes || [];
    if (notes.length) {
      var notesBox = el('div', 'case-notes');
      notes.forEach(function (note) {
        notesBox.appendChild(line('[' + note.created_at + '] '
          + note.author + ': ' + note.body, 'meta'));
      });
      container.appendChild(notesBox);
    }
    if (caseInfo.status === 'closed' && caseInfo.incident_id) {
      var reportBtn = el('button', 'soar-btn btn-primary',
        'Export investigation report (HTML)');
      reportBtn.type = 'button';
      reportBtn.addEventListener('click', function () {
        window.open('/api/incidents/'
          + encodeURIComponent(caseInfo.incident_id) + '/report', '_blank');
      });
      container.appendChild(reportBtn);
    }
  }

  function openCaseForAlert(alertId, container, decision) {
    fetchJSON('/api/alerts/' + encodeURIComponent(alertId) + '/case')
      .then(function (data) {
        if (data.case) {
          reloadDecision(alertId, container, decision);
          return null;
        }
        // Need the incident first: create one, then open the case on it.
        return fetchJSON('/api/alerts/' + encodeURIComponent(alertId)
          + '/incident', {
          method: 'POST', headers: authHeaders(),
          body: JSON.stringify({ actor: 'analyst' }),
        }).then(function (created) {
          return fetchJSON('/api/incidents/'
            + encodeURIComponent(created.incident_id) + '/case', {
            method: 'POST', headers: authHeaders(),
            body: JSON.stringify({ analyst: 'analyst' }),
          });
        }).then(function () {
          reloadDecision(alertId, container, decision);
          refreshAll();
          return null;
        });
      })
      .catch(function (error) {
        container.appendChild(line('Case open failed: ' + error.message,
          'meta soar-err'));
      });
  }

  function reloadDecision(alertId, container, decision) {
    fetchJSON('/api/alerts/' + encodeURIComponent(alertId) + '/decision')
      .then(function (fresh) {
        drawCasePanel(container, { id: alertId }, fresh);
        return null;
      })
      .catch(function (error) {
        container.appendChild(line('Case refresh failed: ' + error.message,
          'meta soar-err'));
      });
  }

  function runSimulation(step) {
    var select = document.getElementById('sim-scenario');
    var scenarioId = select.value;
    var out = document.getElementById('sim-result');
    var headers = authHeaders();
    if (!headers.Authorization) {
      out.replaceChildren(line('Enter the console token above to generate/process '
        + 'scenarios (protected action).', 'meta soar-err'));
      return;
    }
    out.replaceChildren(line(step === 'generate' ?
      'Generating synthetic events …' : 'Processing events through the detection pipeline …'));
    var promise;
    if (step === 'generate') {
      promise = fetchJSON('/api/simulation/scenarios/'
        + encodeURIComponent(scenarioId) + '/generate', {
        method: 'POST', headers: headers,
      }).then(function (run) {
        currentRunId = run.run_id;
        document.getElementById('sim-process').disabled = false;
        return run;
      });
    } else {
      promise = fetchJSON('/api/simulation/scenarios/'
        + encodeURIComponent(scenarioId) + '/process', {
        method: 'POST', headers: headers,
        body: JSON.stringify({ run_id: currentRunId }),
      });
    }
    return promise.then(function (data) {
      if (step === 'generate') {
        out.replaceChildren(line('Run ' + data.run_id + ': '
          + data.event_count + ' synthetic events generated (not yet processed). '
          + 'Now press "Process events".'));
        return null;
      }
      currentRunId = data.run.run_id;
      renderProcessedRun(out, data.run, data.validation);
      refreshAll();
      return null;
    }).catch(function (error) {
      out.replaceChildren(line('Simulation failed: ' + error.message, 'meta soar-err'));
      return null;
    });
  }

  function renderProcessedRun(out, run, validation) {
    var actual = (validation.actual || {});
    var alerts = actual.alerts || [];
    var rows = [
      line('Events generated: ' + run.event_count),
      line('Alerts generated: ' + alerts.length),
      line('SCENARIO VALIDATION — ' + validation.scenario_id + ' : '
        + validation.outcome.toUpperCase()),
      line('Expected: '
        + (validation.expected.detection ? (validation.expected.rule_id + ' / '
          + validation.expected.severity) : 'no detection (benign)')
        + (validation.expected.mitre && validation.expected.mitre.length ?
          ' / MITRE ' + validation.expected.mitre.join(', ') : '')),
    ];
    alerts.forEach(function (alert, index) {
      rows.push(line('Actual alert ' + (index + 1) + ': ' + alert.rule_id
        + ' · severity ' + alert.severity + ' · risk '
        + (alert.risk_score == null ? '—' : alert.risk_score)
        + ' · Jev investigation: ' + String(alert.jev_investigation_required)
        + ' · MITRE ' + ((alert.mitre || []).join(', ') || 'none')));
    });
    if (!alerts.length) {
      rows.push(line('Actual: no alerts — scenario classified as benign and '
        + 'correctly ignored by the deterministic rules.'));
    }
    rows.push(line('Checks: ' + (validation.checks || []).map(function (check) {
      return (check.passed ? '✓ ' : '✗ ') + check.name;
    }).join('   ')));
    rows.push(line('(AI advisory status: '
      + ((actual.ai && actual.ai.available) ? 'analyzed' : 'not analyzed (optional)')
      + '; SOAR can be executed from the alert detail panel.)', 'meta'));
    out.replaceChildren.apply(out, rows);
  }

  // ------------------------------------------------------------------
  // Validation summary
  // ------------------------------------------------------------------

  function updateValidationSummary() {
    return fetchJSON('/api/simulation/summary').then(function (summary) {
      var totals = summary.totals || {};
      document.getElementById('val-total').textContent = String(totals.runs || 0);
      document.getElementById('val-passed').textContent = String(totals.passed || 0);
      document.getElementById('val-warning').textContent = String(totals.warning || 0);
      document.getElementById('val-failed').textContent = String(totals.failed || 0);
      var body = document.getElementById('val-runs');
      var rows = (summary.runs || []).slice(0, 12).map(function (runRow) {
        var row = el('div', 'soar-item');
        row.appendChild(el('span',
          'chip ' + (runRow.outcome === 'passed' ? 'chip-ok' :
            runRow.outcome === 'warning' ? 'chip-wait' : 'chip-bad'),
          runRow.outcome));
        row.appendChild(line(runRow.run_id + ' — ' + runRow.scenario_id
          + ((runRow.failed_checks || []).length ?
            ' (failed: ' + runRow.failed_checks.join(', ') + ')' : '')));
        return row;
      });
      body.replaceChildren.apply(body, rows.length ? rows : [line('No validation runs yet.')]);
    }).catch(function () {});
  }

  // ------------------------------------------------------------------
  // Threat hunt
  // ------------------------------------------------------------------

  function runHunt() {
    var query = document.getElementById('hunt-query').value.trim();
    var out = document.getElementById('hunt-results');
    if (!query) { out.replaceChildren(line('Enter a hunt description.')); return; }
    out.replaceChildren(line('Running hunt …'));
    fetchJSON('/api/hunt/ai', {
      method: 'POST', headers: authHeaders(),
      body: JSON.stringify({ query: query }),
    }).then(function (outcome) {
      var aiFilters = ((outcome.query || {}).filters) || {};
      if (!Object.keys(aiFilters).length) {
        // The provider produced no usable filter (e.g. the offline mock
        // provider) — fall back to the deterministic parser so the hunt
        // still searches real telemetry meaningfully.
        runDeterministicHunt(query, out,
          'AI hunt returned no usable filters — deterministic query parser used.');
        return;
      }
      renderHunt(outcome, out, query);
    }).catch(function (error) {
      // Degrade to the deterministic hunt endpoint on AI rejection.
      out.replaceChildren(line('AI hunt unavailable (' + error.message.slice(0, 80)
        + '); running deterministic hunt instead …', 'meta'));
      runDeterministicHunt(query, out);
    });
  }

  function runDeterministicHunt(query, out, note) {
    var term = query.toLowerCase();
    var filters = {};
    var ipMatch = term.match(/\b\d{1,3}(\.\d{1,3}){3}\b/);
    var events;
    if (ipMatch) {
      filters.src_ip = ipMatch[0];
    } else if (term.indexOf('failed') !== -1 || term.indexOf('auth') !== -1) {
      filters.event_type = 'auth_failed';
    } else if (term.indexOf('dns') !== -1) {
      filters.event_type = 'dns_query';
    } else if (term.indexOf('process') !== -1) {
      filters.event_type = 'process_start';
    } else if (term.indexOf('scan') !== -1) {
      filters.event_type = 'port_scan';
    } else {
      filters.event_type = 'auth_failed';
    }
    events = fetchJSON('/api/hunt?' + new URLSearchParams(filters).toString());
    events.then(function (results) {
      renderHunt({
        status: 'ok', advisory_only: false, query: { filters: filters },
        results: results,
        summary: { status: 'unavailable', reason: 'ai_provider_disabled',
          summary: null, observations: [], confidence: null },
        note: note,
      }, out, query);
    }).catch(function (error) {
      out.replaceChildren(line('Hunt failed: ' + error.message, 'meta soar-err'));
    });
  }

  function renderHunt(outcome, out, queryText) {
    var results = outcome.results || {};
    var rows = (results.results || []).slice(0, 12);
    var aiSummary = outcome.summary || {};
    var body = [
      line('Query: ' + (outcome.query && outcome.query.filters
        ? JSON.stringify(outcome.query.filters) : queryText.slice(0, 120))),
      line('Result count: ' + (results.total || 0)),
    ];
    if (outcome.note) body.push(line(outcome.note, 'meta'));
    rows.forEach(function (eventRow) {
      body.push(line('  ' + eventRow.event_time + ' ' + eventRow.event_type
        + (eventRow.src_ip ? ' src ' + eventRow.src_ip : '')
        + (eventRow.user ? ' user ' + eventRow.user : '')
        + (eventRow.host ? ' host ' + eventRow.host : '')
        + (eventRow.command_line ? ' cmd ' + eventRow.command_line.slice(0, 80) : '')));
    });
    body.push(line('AI summary: '
      + (aiSummary.status === 'ok'
        ? (aiSummary.summary || '(none)')
        : ('unavailable (' + (aiSummary.reason || 'unknown') + ') — raw results '
          + 'shown above; AI is advisory and optional.'))));
    (aiSummary.observations || []).slice(0, 5).forEach(function (observation, i) {
      body.push(line('  observation ' + (i + 1) + ': ' + observation));
    });
    out.replaceChildren.apply(out, body);
  }

  // ------------------------------------------------------------------
  // SOAR panel + audit
  // ------------------------------------------------------------------

  function soarFillList(id, children) {
    var container = document.getElementById(id);
    if (!container) return;
    container.replaceChildren.apply(container,
      children.length ? children : [line('No records.')]);
  }

  function buildPlaybookRow(playbook) {
    var wrap = el('div', 'soar-item');
    var title = el('div');
    title.appendChild(stateChip(playbook.enabled ? 'ENABLED' : 'DISABLED'));
    title.appendChild(line(playbook.playbook_id + ' v' + playbook.version
      + ' — ' + playbook.name + ' (approval: '
      + (playbook.definition || {}).approval_policy + ')'));
    wrap.appendChild(title);
    return wrap;
  }

  function buildExecutionRow(execution) {
    var wrap = el('div', 'soar-item');
    var head = el('div');
    head.appendChild(stateChip(execution.state));
    head.appendChild(line(execution.execution_id + ' — ' + execution.playbook_id
      + ' v' + execution.playbook_version + ' · alert #'
      + (execution.alert_id == null ? '—' : execution.alert_id)));
    head.appendChild(line(execution.dry_run ? 'DRY RUN' : 'REAL EXECUTION',
      execution.dry_run ? 'meta soar-dry' : 'meta soar-real'));
    if (execution.error) head.appendChild(line(execution.error, 'meta soar-err'));
    wrap.appendChild(head);
    (execution.actions || []).forEach(function (action) {
      wrap.appendChild(line('  action[' + action.action_index + '] ' + action.action_type
        + ': ' + action.state, 'meta soar-action'));
    });
    return wrap;
  }

  function buildApprovalRow(approval) {
    var wrap = el('div', 'soar-item');
    wrap.appendChild(stateChip(approval.decision));
    wrap.appendChild(line(approval.approval_id + ' — ' + approval.action_type
      + ' (role: ' + approval.required_role + ')'));
    if (approval.decision === 'pending') {
      var approve = el('button', 'soar-btn', 'Approve');
      var reject = el('button', 'soar-btn soar-btn-bad', 'Reject');
      approve.type = 'button';
      reject.type = 'button';
      approve.addEventListener('click', function () {
        decideApproval(approval.approval_id, 'approve', wrap);
      });
      reject.addEventListener('click', function () {
        decideApproval(approval.approval_id, 'reject', wrap);
      });
      wrap.appendChild(approve);
      wrap.appendChild(reject);
    }
    return wrap;
  }

  function buildIncidentRow(incident) {
    var wrap = el('div', 'soar-item');
    wrap.appendChild(stateChip(incident.status));
    wrap.appendChild(line(incident.incident_id + ' — ' + incident.title + ' ['
      + incident.severity + '] alerts: ' + (incident.alert_ids || []).join(', ')));
    return wrap;
  }

  function buildAuditEntry(entry) {
    var wrap = el('div', 'soar-item');
    wrap.appendChild(line(entry.created_at + ' — ' + entry.actor + ' — '
      + entry.event_type
      + (entry.from_state ? ' · ' + entry.from_state + ' → ' + entry.to_state : '')
      + (entry.dry_run ? ' · DRY RUN' : ' · REAL'), 'meta'));
    if (entry.failure_reason) {
      wrap.appendChild(line(entry.failure_reason, 'meta soar-err'));
    }
    return wrap;
  }

  function fetchSoar() {
    var playbooks = fetchJSON('/api/playbooks').then(function (data) {
      soarFillList('soar-playbooks', (data.playbooks || []).map(buildPlaybookRow));
    });
    var executions = fetchJSON('/api/soar/executions?limit=10').then(function (data) {
      soarFillList('soar-executions', (data.executions || []).map(buildExecutionRow));
    });
    var approvals = fetchJSON('/api/soar/approvals?decision=pending&limit=10')
      .then(function (data) {
        soarFillList('soar-approvals', (data.approvals || []).map(buildApprovalRow));
      });
    var incidents = fetchJSON('/api/incidents?limit=10').then(function (data) {
      soarFillList('soar-incidents', (data.incidents || []).map(buildIncidentRow));
    });
    var audit = fetchSoarAudit();
    var auditFilter = function () { fetchSoarAudit(); };
    var alertFilterEl = document.getElementById('audit-filter-alert');
    if (alertFilterEl && !alertFilterEl.dataset.bound) {
      alertFilterEl.dataset.bound = '1';
      alertFilterEl.addEventListener('change', auditFilter);
      document.getElementById('audit-filter-actor').addEventListener('change', auditFilter);
    }
    return Promise.allSettled([playbooks, executions, approvals, incidents, audit])
      .then(function (results) {
        var failed = results.some(function (r) { return r.status === 'rejected'; });
        if (failed) {
          ['soar-playbooks', 'soar-executions', 'soar-approvals']
            .forEach(function (id) {
              var node = document.getElementById(id);
              if (node && !node.hasChildNodes()) {
                node.replaceChildren(line('SOAR data unavailable.', 'meta'));
              }
            });
        }
      });
  }

  function fetchSoarAudit() {
    var params = new URLSearchParams();
    var alertFilter = document.getElementById('audit-filter-alert');
    var actorFilter = document.getElementById('audit-filter-actor');
    var alertValue = alertFilter && alertFilter.value.trim();
    var actorValue = actorFilter && actorFilter.value.trim();
    var path;
    if (alertValue && /^\d+$/.test(alertValue)) {
      path = '/api/soc/alerts/' + alertValue + '/full';
      return fetchJSON(path).then(function (full) {
        soarFillList('soc-audit', (full.soar.audit || []).slice(0, 30)
          .map(buildAuditEntry));
      });
    }
    if (actorValue) {
      params.set('actor', actorValue);
    }
    var executionRows = fetchJSON('/api/soar/executions?limit=10').then(function (data) {
      var ids = (data.executions || []).map(function (e) { return e.execution_id; });
      return Promise.allSettled(ids.map(function (id) {
        return fetchJSON('/api/soar/executions/'
          + encodeURIComponent(id) + '/audit');
      })).then(function (batches) {
        var rows = [];
        batches.forEach(function (batch) {
          if (batch.status !== 'fulfilled') return;
          var actorMatch = !actorValue ||
            (batch.value.audit || []).some(function (entry) {
              return (entry.actor || '').indexOf(actorValue) !== -1;
            });
          if (actorMatch) rows.push.apply(rows, batch.value.audit || []);
        });
        return rows;
      });
    });
    // Analyst-case decisions are soar_audit rows with no execution; merge
    // them in so the trail is complete (workflow events + case events).
    var caseRows = fetchJSON('/api/soc/case-audit?limit=40').then(function (data) {
      return (data.audit || []).filter(function (entry) {
        return !actorValue || (entry.actor || '').indexOf(actorValue) !== -1;
      });
    }).catch(function () { return []; });
    return Promise.allSettled([executionRows, caseRows]).then(function (results) {
      var rows = [];
      results.forEach(function (result) {
        if (result.status === 'fulfilled' && Array.isArray(result.value)) {
          rows.push.apply(rows, result.value);
        }
      });
      rows.sort(function (a, b) {
        return (b.created_at || '').localeCompare(a.created_at || '');
      });
      soarFillList('soc-audit', rows.slice(0, 40).map(buildAuditEntry));
    });
  }

  // ------------------------------------------------------------------
  // SOC command bar, workers, live event stream (all data-derived)
  // ------------------------------------------------------------------

  var WORKER_DEFS = [
    ['ingest', 'INGEST WORKER'],
    ['detection', 'DETECTION WORKER'],
    ['correlation', 'CORRELATION WORKER'],
    ['intel', 'THREAT INTEL WORKER'],
    ['risk', 'RISK WORKER'],
    ['jev', 'JEV DECISION WORKER'],
    ['ai', 'AI ANALYST'],
    ['rag', 'RAG RETRIEVAL'],
    ['incident', 'INCIDENT WORKER'],
    ['soar', 'SOAR WORKER'],
  ];
  var workerStates = {};
  WORKER_DEFS.forEach(function (def) { workerStates[def[0]] = 'ONLINE'; });

  function setWorker(name, state) {
    if (name in workerStates) {
      workerStates[name] = state;
      renderWorkers();
    }
  }

  function setWorkers(state) {
    WORKER_DEFS.forEach(function (def) { workerStates[def[0]] = state; });
    renderWorkers();
  }

  function renderWorkers() {
    var host = document.getElementById('soc-workers');
    if (!host) return;
    var rows = WORKER_DEFS.map(function (def) {
      var state = workerStates[def[0]] || 'ONLINE';
      var wrap = el('div', 'worker worker-' + state.toLowerCase().replace('_', '-'));
      var dot = el('span', 'worker-dot');
      wrap.appendChild(dot);
      wrap.appendChild(el('span', 'worker-name', def[1]));
      wrap.appendChild(el('span', 'worker-state', '● ' + state));
      return wrap;
    });
    host.replaceChildren.apply(host, rows);
  }

  function setPill(id, text, cls) {
    var node = document.getElementById(id);
    if (!node) return;
    node.textContent = text;
    node.className = 'pill' + (cls ? ' ' + cls : '');
  }

  var lastStreamCount = 0;
  var lastStreamPoll = 0;
  var firedEventIds = {};

  function refreshEventStream() {
    return fetchJSON('/api/events/recent?limit=40').then(function (data) {
      var events = data.events || [];
      var host = document.getElementById('event-stream');
      if (!host) return;
      var rows = events.map(function (event) {
        var row = el('div', 'stream-row');
        if (firedEventIds[event.event_id]) row.className += ' stream-fired';
        if (event.source === 'soc-simulation') {
          row.appendChild(el('span', 'chip chip-sim', 'LIVE SYNTHETIC'));
        }
        row.appendChild(el('span', 'stream-time',
          (event.ingestion_time || '').replace('T', ' ').slice(0, 19)));
        row.appendChild(el('span', 'stream-type', event.event_type || '?'));
        row.appendChild(el('span', 'stream-entity',
          (event.src_ip || '—') + (event.dst_ip ? ' → ' + event.dst_ip
            + (event.dst_port ? ':' + event.dst_port : '') : '')));
        row.appendChild(el('span', 'stream-entity',
          (event.host || '—') + (event.user_name ? ' / ' + event.user_name : '')));
        row.appendChild(el('span', 'stream-result',
          (event.action || '') + (event.outcome ? ' ' + event.outcome : '')));
        return row;
      });
      host.replaceChildren.apply(host, rows.length ? rows :
        [line('No events yet — run a scenario in the Simulation Lab.', 'meta')]);
      // events/sec derived from actual poll deltas (real data, no fake rate).
      var now = Date.now();
      if (lastStreamPoll) {
        var delta = Math.max(0, events.length - lastStreamCount);
        var seconds = Math.max(0.5, (now - lastStreamPoll) / 1000);
        var epsNode = document.getElementById('tb-eps');
        if (epsNode) epsNode.textContent = String(Math.round(delta / seconds));
      }
      lastStreamCount = events.length;
      lastStreamPoll = now;
      var newest = events.length ? events[0].ingestion_time : null;
      var lastNode = document.getElementById('tb-last-event');
      if (lastNode && newest) {
        lastNode.textContent = 'last event: ' + newest.replace('T', ' ').slice(0, 19);
      }
    }).catch(function () {});
  }

  // ------------------------------------------------------------------
  // Distribution bars (severity / MITRE / top sources) — pure DOM
  // ------------------------------------------------------------------

  function buildBars(containerId, entries) {
    var host = document.getElementById(containerId);
    if (!host) return;
    var rows = entries.map(function (entry) {
      var wrap = el('div', 'bar-row');
      wrap.appendChild(el('span', 'bar-label', entry.label));
      var track = el('span', 'bar-track');
      var fill = el('span', 'bar-fill ' + (entry.cls || ''));
      fill.style.width = Math.max(4, entry.pct) + '%';
      track.appendChild(fill);
      wrap.appendChild(track);
      wrap.appendChild(el('span', 'bar-value', String(entry.value)));
      return wrap;
    });
    host.replaceChildren.apply(host, rows.length ? rows :
      [line('No data yet.', 'meta')]);
  }

  function renderSeverityBars(overview) {
    var entries = [
      { label: 'CRITICAL', value: overview.critical_alerts || 0, cls: 'bar-crit' },
      { label: 'HIGH', value: overview.high_alerts || 0, cls: 'bar-high' },
      { label: 'MEDIUM', value: overview.medium_alerts || 0, cls: 'bar-med' },
      { label: 'LOW', value: overview.low_alerts || 0, cls: 'bar-low' },
    ];
    var max = Math.max.apply(null, entries.map(function (e) { return e.value; }).concat([1]));
    entries.forEach(function (entry) { entry.pct = entry.value * 100 / max; });
    buildBars('bar-severity', entries);
  }

  function renderMitreBars(alerts) {
    var counts = {};
    (alerts || []).forEach(function (alert) {
      // Queue rows carry flattened 'mitre_techniques'; run views use 'mitre'.
      var techniques = alert.mitre_techniques || alert.mitre || [];
      techniques.forEach(function (technique) {
        counts[technique] = (counts[technique] || 0) + 1;
      });
    });
    var entries = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a];
    }).slice(0, 6).map(function (technique) {
      return { label: technique, value: counts[technique], cls: 'bar-mitre' };
    });
    var max = Math.max.apply(null, entries.map(function (e) { return e.value; }).concat([1]));
    entries.forEach(function (entry) { entry.pct = entry.value * 100 / max; });
    buildBars('bar-mitre', entries);
  }

  function renderSourceBars(alerts) {
    var counts = {};
    (alerts || []).forEach(function (alert) {
      (alert.source_ips || []).forEach(function (ip) {
        counts[ip] = (counts[ip] || 0) + 1;
      });
    });
    var entries = Object.keys(counts).sort(function (a, b) {
      return counts[b] - counts[a];
    }).slice(0, 6).map(function (ip) {
      return { label: ip, value: counts[ip], cls: 'bar-src' };
    });
    var max = Math.max.apply(null, entries.map(function (e) { return e.value; }).concat([1]));
    entries.forEach(function (entry) { entry.pct = entry.value * 100 / max; });
    buildBars('bar-sources', entries);
  }

  // ------------------------------------------------------------------
  // Simulation pipeline runner (stages map to real backend calls)
  // ------------------------------------------------------------------

  var PIPELINE_STAGES = [
    'Generating synthetic events',
    'Ingesting',
    'Normalizing',
    'Running detections',
    'Correlating',
    'Threat intelligence',
    'Risk scoring',
    'Jev decision',
    'AI investigation',
    'Incident evaluation',
    'SOAR evaluation',
    'Complete',
  ];

  function renderPipelineProgress(stageIndex) {
    var host = document.getElementById('sim-progress');
    if (!host) return;
    var rows = PIPELINE_STAGES.map(function (name, index) {
      var cls = 'pipe-step';
      if (index < stageIndex) cls += ' pipe-done';
      if (index === stageIndex) cls += ' pipe-active';
      var mark = index < stageIndex ? '✓' : (index === stageIndex ? '▸' : '·');
      return el('div', cls, '[' + (index + 1) + '] ' + mark + ' ' + name);
    });
    host.replaceChildren.apply(host, rows);
  }

  function requireToken(out) {
    var headers = authHeaders();
    if (!headers.Authorization) {
      out.replaceChildren(line('Enter the console token above first (protected '
        + 'action).', 'meta soar-err'));
      return null;
    }
    return headers;
  }

  function runFullPipeline() {
    var out = document.getElementById('sim-result');
    var headers = requireToken(out);
    if (!headers) return;
    var scenarioId = document.getElementById('sim-scenario').value;
    setPill('pill-sim', 'SIM: RUNNING', 'pill-run');
    setWorkers('PROCESSING');
    var stage = 0;
    renderPipelineProgress(stage);
    out.replaceChildren(line('Running ' + scenarioId + ' through the real pipeline …'));
    var progressTimer = setInterval(function () {
      stage = Math.min(stage + 1, PIPELINE_STAGES.length - 2);
      renderPipelineProgress(stage);
      if (stage === 3) {
        setWorker('detection', 'PROCESSING');
        setPill('pill-detection', 'DETECTION: SCANNING', 'pill-run');
      }
      if (stage === 5) setWorker('intel', 'PROCESSING');
      if (stage === 7) setWorker('jev', 'PROCESSING');
    }, 180);
    var pipeline = document.getElementById('sim-pipeline');
    if (pipeline) pipeline.replaceChildren();
    var attackPath = document.getElementById('attack-path');
    if (attackPath) attackPath.replaceChildren();
    fetchJSON('/api/simulation/scenarios/' + encodeURIComponent(scenarioId) + '/generate', {
      method: 'POST', headers: headers,
    }).then(function (run) {
      currentRunId = run.run_id;
      document.getElementById('sim-process').disabled = false;
      return fetchJSON('/api/simulation/scenarios/' + encodeURIComponent(scenarioId)
        + '/process', {
        method: 'POST', headers: headers,
        body: JSON.stringify({ run_id: run.run_id }),
      });
    }).then(function (data) {
      clearInterval(progressTimer);
      renderPipelineProgress(PIPELINE_STAGES.length - 1);
      currentRunId = data.run.run_id;
      renderProcessedRun(out, data.run, data.validation);
      setPill('pill-sim', 'SIM: READY', 'pill-ok');
      setPill('pill-detection', 'DETECTION: ONLINE', 'pill-ok');
      setWorkers('ONLINE');
      return renderRunPipeline(data.run.run_id);
    }).catch(function (error) {
      clearInterval(progressTimer);
      setPill('pill-sim', 'SIM: READY', 'pill-ok');
      setWorkers('ONLINE');
      out.replaceChildren(line('Simulation failed: ' + error.message, 'meta soar-err'));
    });
  }

  function renderRunPipeline(runId) {
    return fetchJSON('/api/simulation/runs/' + encodeURIComponent(runId) + '/events')
      .then(function (data) {
        firedEventIds = {};
        (data.alerts || []).forEach(function (alert) {
          var ids = alert.source_event_ids || [];
          ids.forEach(function (id) { firedEventIds[id] = true; });
        });
        var host = document.getElementById('sim-pipeline');
        if (host) {
          var rows = [el('div', 'pipe-title', 'RUN ' + data.run_id + ' — '
            + data.scenario_id + ' (' + data.status + ')')];
          (data.events || []).forEach(function (event) {
            var row = el('div', 'pipe-event'
              + (firedEventIds[event.event_id] ? ' pipe-event-fired' : ''));
            row.appendChild(el('span', 'stream-time',
              (event.event_time || '').slice(11, 19)));
            row.appendChild(el('span', 'stream-type', event.event_type || '?'));
            row.appendChild(el('span', 'stream-entity',
              (event.src_ip || '—') + (event.user_name ? ' / ' + event.user_name : '')));
            row.appendChild(el('span', 'stream-result', firedEventIds[event.event_id]
              ? '→ contributed to alert' : 'processed'));
            rows.push(row);
          });
          (data.alerts || []).forEach(function (alert) {
            var row = el('div', 'pipe-alert');
            row.appendChild(el('span', 'chip ' + (severityClasses[alert.severity]
              || 'unknown'), alert.severity || '?'));
            row.appendChild(line('DETECTION FIRED → ALERT #' + alert.id + ' · '
              + alert.rule_id + ' · risk ' + (alert.deterministic_risk_score == null
                ? '—' : alert.deterministic_risk_score) + '/100 · Jev '
              + (alert.jev_priority || '—') + ' · MITRE '
              + ((alert.mitre || []).join(', ') || '—')));
            rows.push(row);
          });
          if (!(data.alerts || []).length) {
            rows.push(el('div', 'pipe-event',
              'No detection fired — events processed and stored only.'));
          }
          host.replaceChildren.apply(host, rows);
        }
        setWorker('detection', (data.alerts || []).length ? 'PROCESSING' : 'ONLINE');
        setPill('pill-detection', (data.alerts || []).length
          ? 'DETECTION: FIRED' : 'DETECTION: ONLINE',
          (data.alerts || []).length ? 'pill-run' : 'pill-ok');
        if ((data.alerts || []).length) {
          renderAttackPath(data);
        } else if (document.getElementById('attack-path')) {
          document.getElementById('attack-path').replaceChildren();
        }
        refreshEventStream();
        return null;
      }).catch(function () {});
  }

  function attackPathRow(text, cls) {
    var wrap = el('div', 'ap-step' + (cls ? ' ' + cls : ''));
    wrap.appendChild(el('span', 'ap-node', text));
    return wrap;
  }

  function attackPathArrow(label) {
    var wrap = el('div', 'ap-arrow');
    wrap.appendChild(el('span', 'ap-arrow-line', '|'));
    wrap.appendChild(el('span', 'ap-arrow-label', label));
    wrap.appendChild(el('span', 'ap-arrow-line', '↓'));
    return wrap;
  }

  function renderAttackPath(runData) {
    var host = document.getElementById('attack-path');
    if (!host) return;
    var alert = (runData.alerts || [])[0];
    var firstEvent = (runData.events || [])[0] || {};
    var rows = [el('div', 'pipe-title', 'ATTACK PATH — derived from stored evidence')];
    rows.push(attackPathRow('ATTACKER ' + (firstEvent.src_ip || '—')));
    rows.push(attackPathArrow((runData.events || []).length + ' synthetic events'));
    rows.push(attackPathRow((firstEvent.dst_ip || firstEvent.host || 'TARGET')));
    rows.push(attackPathArrow('detection'));
    rows.push(attackPathRow('DETECTION ' + (alert ? alert.rule_id : '—')
      + (alert ? ' · ' + alert.severity + ' · risk ' + alert.deterministic_risk_score
        + '/100' : ''), 'ap-hot'));
    rows.push(attackPathArrow('Jev (deterministic, not AI)'));
    rows.push(attackPathRow('JEV: ' + (alert ? ((alert.jev_priority || '—')
      + (alert.jev_investigation_required ? ' · INVESTIGATE' : '')) : '—'), 'ap-hot'));
    rows.push(attackPathArrow('MITRE ATT&CK'));
    rows.push(attackPathRow('ATT&CK: ' + ((alert && alert.mitre || []).join(', ') || '—')));
    rows.push(attackPathArrow('AI analyst (advisory)'));
    rows.push(attackPathRow('AI: ' + ((alert && alert.mitre) ? 'analysis available in alert detail' : 'not run — deterministic engine unaffected'), 'ap-ai'));
    rows.push(attackPathArrow('response'));
    rows.push(attackPathRow('INCIDENT + SOAR DRY-RUN + HUMAN APPROVAL', 'ap-hot'));
    rows.push(line('Open the alert in the queue to run AI, create the incident, and '
      + 'execute the SOAR playbook (approval-gated, dry-run).', 'meta'));
    host.replaceChildren.apply(host, rows);
  }

  // ------------------------------------------------------------------
  // Demonstration mode (real pipeline; approval stays human)
  // ------------------------------------------------------------------

  function renderDemoStep(container, step) {
    var row = el('div', 'demo-step');
    row.appendChild(el('span', 'chip chip-run', String(step.step)));
    row.appendChild(el('span', 'demo-step-name', step.name));
    row.appendChild(el('span', 'demo-step-detail', step.detail));
    container.appendChild(row);
  }

  function runDemo() {
    var out = document.getElementById('demo-steps');
    var headers = requireToken(out);
    if (!headers) return;
    out.replaceChildren(line('Running the guided SOC demo on the real pipeline …'));
    setPill('pill-sim', 'SIM: DEMO', 'pill-run');
    setWorkers('PROCESSING');
    fetchJSON('/api/simulation/demo', { method: 'POST', headers: headers })
      .then(function (demo) {
        setPill('pill-sim', 'SIM: READY', 'pill-ok');
        setWorkers('ONLINE');
        out.replaceChildren();
        (demo.steps || []).forEach(function (step, index) {
          setTimeout(function () { renderDemoStep(out, step); }, index * 280);
        });
        setTimeout(function () {
          if (demo.approval_id) {
            var row = el('div', 'demo-step');
            row.appendChild(el('span', 'chip chip-wait', 'GATE'));
            row.appendChild(el('span', 'demo-step-name', 'human approval required'));
            var approve = el('button', 'soar-btn', 'Approve & complete dry-run');
            approve.type = 'button';
            approve.addEventListener('click', function () {
              decideApproval(demo.approval_id, 'approve', row);
              fetchJSON('/api/soar/executions/' + encodeURIComponent(demo.execution_id)
                + '/advance', { method: 'POST', headers: headers,
                  body: JSON.stringify({ actor: 'analyst' }) })
                .then(function (execution) {
                  row.appendChild(line('Execution is now ' + execution.state
                    + ' (dry-run, simulated only).', 'ask-ans'));
                  refreshAll();
                  return null;
                }).catch(function (error) {
                  row.appendChild(line('Advance failed: ' + error.message,
                    'meta soar-err'));
                  return null;
                });
            });
            row.appendChild(approve);
            out.appendChild(row);
          }
          refreshAll();
        }, (demo.steps || []).length * 280 + 120);
      })
      .catch(function (error) {
        setPill('pill-sim', 'SIM: READY', 'pill-ok');
        setWorkers('ONLINE');
        out.replaceChildren(line('Demo failed: ' + error.message, 'meta soar-err'));
      });
  }

  function resetDemo() {
    var out = document.getElementById('demo-steps');
    var headers = requireToken(out);
    if (!headers) return;
    fetchJSON('/api/simulation/reset', { method: 'POST', headers: headers })
      .then(function (result) {
        out.replaceChildren(line('Simulation-lab data cleared: '
          + JSON.stringify(result) + ' — alerts, events, incidents, investigations,'
          + ' approvals, SOAR executions and validation runs from the lab are gone.'
          + ' Configuration, rules and knowledge base untouched.', 'ask-ans'));
        refreshAll();
        refreshEventStream();
        return null;
      })
      .catch(function (error) {
        out.replaceChildren(line('Reset failed: ' + error.message, 'meta soar-err'));
      });
  }

  // ------------------------------------------------------------------
  // Full SOC validation runner
  // ------------------------------------------------------------------

  function runFullValidation() {
    var progress = document.getElementById('val-progress');
    var headers = requireToken(progress);
    if (!headers) return;
    progress.replaceChildren(line('Executing all 15 scenarios through the real '
      + 'pipeline (generate → process → validate) …'));
    var button = document.getElementById('val-run-all');
    if (button) button.disabled = true;
    setPill('pill-sim', 'SIM: VALIDATING', 'pill-run');
    fetchJSON('/api/simulation/validate-all', { method: 'POST', headers: headers })
      .then(function (report) {
        if (button) button.disabled = false;
        setPill('pill-sim', 'SIM: READY', 'pill-ok');
        progress.replaceChildren(line('Validation complete at '
          + (report.generated_at || '').replace('T', ' ').slice(0, 19)
          + ' — every scenario ran against the real engine.'));
        renderValidationReport(report);
        updateValidationSummary();
        return null;
      })
      .catch(function (error) {
        if (button) button.disabled = false;
        setPill('pill-sim', 'SIM: READY', 'pill-ok');
        progress.replaceChildren(line('Validation failed: ' + error.message,
          'meta soar-err'));
      });
  }

  function renderValidationReport(report) {
    var totals = report.totals || {};
    document.getElementById('val-total').textContent = String(totals.scenarios || 0);
    document.getElementById('val-passed').textContent = String(totals.passed || 0);
    document.getElementById('val-warning').textContent = String(totals.warning || 0);
    document.getElementById('val-failed').textContent = String(totals.failed || 0);
    var body = document.getElementById('val-table-body');
    if (!body) return;
    var rows = (report.results || []).map(function (result) {
      var tr = el('tr', 'val-row');
      var expected = result.expected.detection
        ? (result.expected.rule_id + ' / ' + result.expected.severity)
        : 'no alert';
      var alerts = (result.actual.alerts || []);
      var actual = alerts.length
        ? alerts.map(function (a) { return a.rule_id; }).join(' + ')
        : 'no alert';
      var first = alerts[0] || {};
      var ai = result.actual.ai || {};
      var aiText = ai.available ? ('analyzed ×' + ai.available) : 'not analyzed';
      var checks = (result.failed_checks || []).length
        ? 'failed: ' + result.failed_checks.join(', ') : 'all green';
      var outcome = result.outcome.toUpperCase();
      if (result.false_positive) outcome += ' (designed FP)';
      tr.appendChild(el('td', 'queue-strong', result.name));
      tr.appendChild(queueCell(expected));
      tr.appendChild(queueCell(actual));
      tr.appendChild(queueCell(first.severity));
      tr.appendChild(queueCell(first.risk_score == null ? null
        : first.risk_score + '/100'));
      tr.appendChild(queueCell(first.jev_priority));
      tr.appendChild(queueCell(((first.mitre || []).join(', ')) || null));
      tr.appendChild(queueCell(aiText));
      tr.appendChild(queueCell(checks));
      var outcomeCell = queueCell(null);
      outcomeCell.appendChild(stateChip(result.outcome === 'passed' ? 'ok'
        : result.outcome === 'warning' ? 'PENDING' : 'ACTION_FAILED'));
      outcomeCell.appendChild(line(outcome));
      tr.appendChild(outcomeCell);
      return tr;
    });
    body.replaceChildren.apply(body, rows);
  }

  // ------------------------------------------------------------------
  // Refresh loop
  // ------------------------------------------------------------------

  function refreshAll() {
    updateOverview().catch(function () {});
    fetchAlerts();
    updateValidationSummary();
    fetchSoar();
  }

  filterSel.addEventListener('change', fetchAlerts);
  document.getElementById('refreshBtn').addEventListener('click', fetchAlerts);
  document.getElementById('sim-generate').addEventListener('click', function () {
    runSimulation('generate');
  });
  document.getElementById('sim-process').addEventListener('click', function () {
    runSimulation('process');
  });
  var pipelineBtn = document.getElementById('sim-run-pipeline');
  if (pipelineBtn) pipelineBtn.addEventListener('click', runFullPipeline);
  var demoBtn = document.getElementById('demo-start');
  if (demoBtn) demoBtn.addEventListener('click', runDemo);
  var resetBtn = document.getElementById('demo-reset');
  if (resetBtn) resetBtn.addEventListener('click', resetDemo);
  var valBtn = document.getElementById('val-run-all');
  if (valBtn) valBtn.addEventListener('click', runFullValidation);
  var replayBtn = document.getElementById('replay-start');
  if (replayBtn) replayBtn.addEventListener('click', startReplay);
  var replayResetBtn = document.getElementById('replay-reset');
  if (replayResetBtn) replayResetBtn.addEventListener('click', resetReplay);
  document.getElementById('hunt-run').addEventListener('click', runHunt);
  fetchAlerts();
  fetchSoar();
  updateOverview();
  updateValidationSummary();
  renderWorkers();
  refreshEventStream();
  loadScenarioCatalog()
    .then(function () { return null; })
    .catch(function () {
      document.getElementById('sim-desc').textContent =
        'Scenario catalog unavailable — is the local service running?';
    });
  setInterval(fetchAlerts, 1500);
  setInterval(function () {
    updateOverview(); updateValidationSummary(); fetchSoar(); refreshDetailSoar();
  }, 5000);
  setInterval(refreshEventStream, 3000);
})();
