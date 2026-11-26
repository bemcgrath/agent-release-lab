"use strict";

const $ = (id) => document.getElementById(id);
const state = { token: "", demo: true, generation: 0, agent: null, detail: null, audit: [] };
const labels = {
  eligible: "Eligible", blocked: "Blocked", pending: "Awaiting human decision",
  approved: "Historically approved", declined: "Declined", stale: "Assessment stale",
  not_evaluated: "Deployment authorization not evaluated",
};
const tone = { eligible: "good", blocked: "bad", approved: "history", declined: "bad", pending: "pending", stale: "pending" };

function node(tag, cls, value) {
  const result = document.createElement(tag);
  if (cls) result.className = cls;
  if (value !== undefined) result.textContent = value;
  return result;
}

function words(value) {
  const text = String(value ?? "");
  return Object.hasOwn(labels, text) ? labels[text] : text.replaceAll("_", " ");
}

function short(value) {
  return value ? value.slice(0, 12) : "—";
}

function code(value) {
  const output = node("code", "", short(value));
  if (value) output.title = value;
  return output;
}

function stamp(value) {
  if (!value) return "—";
  return new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function badge(value, text = words(value)) {
  return node("span", "badge " + (tone[value] || "neutral"), text);
}

function empty(message) {
  return node("p", "muted", message);
}

function table(headings, rows, absent = "No entries.") {
  if (!rows.length) return empty(absent);
  const wrapper = node("div", "table-wrap");
  const grid = node("table");
  const header = grid.createTHead().insertRow();
  headings.forEach((heading) => header.append(node("th", "", heading)));
  const body = grid.createTBody();
  rows.forEach((row) => {
    const line = body.insertRow();
    row.forEach((value) => {
      const cell = line.insertCell();
      if (value instanceof Node) cell.append(value);
      else cell.textContent = value ?? "—";
    });
  });
  wrapper.append(grid);
  return wrapper;
}

function list(values) {
  const output = node("ul", "items");
  values.forEach((value) => output.append(node("li", "", value)));
  return output;
}

function options(select, values, current) {
  select.replaceChildren(...values.map(([id, label]) => {
    const option = node("option", "", label);
    option.value = id;
    option.selected = id === current;
    return option;
  }));
}

function notice(message = "", error = false) {
  $("notice").textContent = message;
  $("notice").classList.toggle("error", error);
}

async function api(path, options = {}) {
  const headers = {};
  if (state.token) headers.Authorization = "Bearer " + state.token;
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method: options.method || "GET", headers, cache: "no-store",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(typeof payload.detail === "string" ? payload.detail :
      payload.authorization === "stale" ? "Assessment became stale. Submit a fresh assessment before approving." :
        "Request failed (" + response.status + ").");
  }
  return payload;
}

function renderInventory(inventory, active) {
  options($("agents"), inventory.map((entry) => [
    entry.agent_id, entry.agent_id + " · " + (entry.ownership?.owner_id || "unassigned"),
  ]), active);
  $("agents").disabled = state.demo || inventory.length === 0;
}

function renderHistory(history, assessmentId) {
  const assessments = history.assessments;
  options($("assessments"), assessments.map((item) => [
    item.assessment_id, short(item.candidate_fingerprint) + " · " + words(item.eligibility) + " · " + stamp(item.assessed_at),
  ]), assessmentId);
  $("assessment-picker").hidden = state.demo || assessments.length === 0;
  const latest = new Map();
  [...assessments].reverse().forEach((item) => latest.set(item.candidate_fingerprint, item));
  $("release-data").replaceChildren(table(
    ["Candidate", "Purpose", "Latest gate", "Human decision"],
    history.candidates.map((candidate) => {
      const item = latest.get(candidate.fingerprint);
      return [code(candidate.fingerprint), words(candidate.purpose || "—"),
        item ? badge(item.eligibility) : "Unassessed", item ? badge(item.authorization) : "—"];
    }), "No registered candidates.",
  ));
}

function format(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value !== "object") return String(value);
  if ("id" in value) return value.id + (value.revision ? " @ " + value.revision : " @ " + short(value.digest));
  return JSON.stringify(value);
}

function renderGovernance(assessment, controls) {
  $("governance-data").replaceChildren(
    list([
      "Risk tier: " + words(assessment.risk_tier || "Unresolved"),
      "Policy: " + short(assessment.policy_fingerprint),
      "Baseline: " + short(assessment.baseline_fingerprint),
      ...Object.entries(assessment.risk_dimensions).map(([name, value]) => words(name) + ": " + words(value.value)),
    ]),
    table(["Required control", "Requirement"], Object.entries(controls).map(([key, control]) => {
      const detail = node("details");
      detail.append(node("summary", "", control.check_id + " · " + control.max_age_seconds.toLocaleString() + " s"),
        list([
          "Producers: " + control.producers.join(", "),
          ...Object.entries(control.accepted_suites).map(([fingerprint, revision]) => "Suite " + fingerprint + " @ " + revision),
        ]));
      return [words(key), detail];
    }), "No resolved controls."),
    table(["Gate result", "Control"], assessment.reasons.map((reason) => [
      words(reason.code), reason.control || "—",
    ]), "No gate reasons recorded."),
  );
}

function renderEvidence(assessment, evidence) {
  $("evidence-data").replaceChildren(
    table(["Evidence", "Result", "Producer", "Record"], evidence.map((item) => [
      item.evidence_id, item.available ? item.result : "Unavailable", item.producer || "—", code(item.record_fingerprint),
    ]), "No evidence available for this assessment."),
    table(["Predecessor", "Superseded by"], assessment.reasons
      .filter((reason) => reason.superseded_by)
      .map((reason) => [reason.evidence_id, reason.superseded_by]), "No supersession recorded."),
  );
}

function renderAdvisory(reviews) {
  const panel = $("advisory-data");
  const review = reviews[0];
  if (!review) {
    panel.replaceChildren(empty("No advisory review yet."));
    return;
  }
  const summary = empty([
    review.model || review.requested_model, "Prompt " + review.prompt_version,
    stamp(review.reviewed_at), review.latency_ms + " ms", words(review.status),
  ].join(" · "));
  panel.replaceChildren(summary);
  const trace = node("details", "muted");
  trace.append(node("summary", "", "Review trace"), list([
    "Prompt fingerprint: " + review.prompt_fingerprint,
    "Input fingerprint: " + review.input_fingerprint,
    "Output fingerprint: " + (review.output_fingerprint || "Unavailable"),
    ...(review.usage ? [
      "Usage: " + review.usage.input_tokens + " input, " + review.usage.output_tokens
        + " output tokens (" + review.usage.source + ")",
    ] : []),
  ]));
  panel.append(trace);
  if (review.status !== "completed") {
    panel.append(empty(words(review.reason)));
  } else if (!review.findings.length) {
    panel.append(empty("The reviewer returned no findings for this snapshot."));
  } else {
    const findings = node("div", "findings");
    review.findings.forEach((item) => {
      const card = node("article", "finding");
      card.append(node("h3", "", words(item.category)), badge(item.severity === "high" ? "bad" : "pending", words(item.severity)));
      const data = node("div", "finding-details");
      data.append(node("p", "", item.description), node("p", "", item.remediation));
      const citations = item.evidence.map((citation) => citation.evidence_id + " / " + short(citation.record_fingerprint));
      data.append(empty("Confidence " + item.confidence + "%"));
      if (citations.length) data.append(list(citations));
      if (item.uncertainty) data.append(empty(item.uncertainty));
      card.append(data);
      findings.append(card);
    });
    panel.append(findings);
  }
  if (reviews.length > 1) panel.append(table(["Previous review", "Model", "Result"],
    reviews.slice(1).map((item) => [stamp(item.reviewed_at), item.model || item.requested_model, words(item.status)])));
}

function renderApproval(assessment) {
  const remaining = assessment.required_roles.filter((role) => !assessment.approvals.some((item) => item.role === role));
  options($("approval-role"), remaining.map((role) => [role, words(role)]));
  $("approval-form").hidden = state.demo || assessment.authorization !== "pending" || remaining.length === 0;
  const statuses = node("div", "status-group");
  statuses.append(badge(assessment.authorization), badge(assessment.deployment_authorization));
  const roles = assessment.required_roles.length ? assessment.required_roles.map(words).join(", ") : "Unresolved";
  $("approval-data").replaceChildren(
    statuses, empty("Required roles: " + roles),
    table(["Actor", "Role", "Decision"], assessment.approvals.map((action) => [action.actor, action.role, action.decision]),
      "No human decisions recorded."),
  );
}

function renderDetail(detail) {
  state.detail = detail;
  $("review-action").hidden = state.demo || !detail;
  if (!detail) {
    $("overview-status").replaceChildren();
    ["comparison-data", "governance-data", "evidence-data", "advisory-data", "approval-data"]
      .forEach((id) => $(id).replaceChildren(empty("Select a recorded assessment.")));
    $("approval-form").hidden = true;
    return;
  }
  const assessment = detail.assessment;
  $("overview-status").replaceChildren(badge(assessment.eligibility), badge(assessment.authorization),
    badge(assessment.deployment_authorization));
  $("comparison-data").replaceChildren(table(["Field", "Baseline", "Candidate", "Categories"], detail.changes.map(
    (change) => [change.field, format(change.before), format(change.after), change.categories.map(words).join(", ")],
  ), "No component changes against this baseline."));
  renderGovernance(assessment, detail.controls);
  renderEvidence(assessment, detail.evidence);
  renderAdvisory(detail.reviews);
  renderApproval(assessment);
}

function renderAudit(events) {
  state.audit = events;
  $("audit-more").hidden = state.demo || events.length === 0 || events.length % 100 !== 0;
  $("audit-data").replaceChildren(table(["Time", "Event", "Actor", "Record"], events.map((event) => {
    const detail = node("details");
    const record = node("pre", "audit-record");
    record.append(node("code", "", JSON.stringify(event.details, null, 2)));
    detail.append(node("summary", "", "View record"), record);
    return [stamp(event.occurred_at), words(event.event), event.actor, detail];
  }), "No audit events available."));
}

function applyMode(demo) {
  state.demo = demo;
  $("mode-label").textContent = demo ? "Synthetic demo" : "Local registry";
  $("scenarios").disabled = !demo;
  $("connect").hidden = !demo;
  $("demo-return").hidden = demo;
}

function resetView() {
  state.agent = null;
  renderInventory([], null);
  renderDetail(null);
  renderAudit([]);
  $("assessment-picker").hidden = true;
  $("release-data").replaceChildren();
  $("agent-owner").textContent = "";
}

async function loadDemo() {
  const generation = ++state.generation;
  state.token = "";
  applyMode(true);
  resetView();
  $("agent-title").textContent = "Ledger Finch";
  notice("Loading the selected synthetic scenario…");
  try {
    const data = await api("/v1/demo/ledger-finch/" + encodeURIComponent($("scenarios").value));
    if (generation !== state.generation) return;
    renderInventory(data.inventory, data.history.agent_id);
    $("agent-owner").textContent = "Accountable owner: " + (data.history.ownership?.owner_id || "unassigned");
    renderHistory(data.history, data.detail.assessment.assessment_id);
    renderDetail(data.detail);
    renderAudit(data.audit);
    notice("Synthetic evidence and human decisions in this view are isolated from your registry.");
  } catch (error) {
    if (generation === state.generation) notice(error.message, true);
  }
}

async function loadLive(agent, assessmentId) {
  const generation = ++state.generation;
  state.agent = agent;
  renderDetail(null);
  renderAudit([]);
  $("assessment-picker").hidden = true;
  $("release-data").replaceChildren();
  $("agent-title").textContent = agent;
  $("agent-owner").textContent = "";
  notice("Reading local registry…");
  try {
    const root = "/v1/dashboard/agents/" + encodeURIComponent(agent);
    const [history, audit] = await Promise.all([
      api(root + "/releases"),
      api("/v1/governance/agents/" + encodeURIComponent(agent) + "/audit"),
    ]);
    if (generation !== state.generation) return;
    const id = assessmentId || history.assessments[0]?.assessment_id;
    $("agent-owner").textContent = "Accountable owner: " + (history.ownership?.owner_id || "unassigned");
    renderHistory(history, id);
    renderAudit(audit.events);
    if (id) {
      const detail = await api("/v1/dashboard/assessments/" + encodeURIComponent(id));
      if (generation !== state.generation) return;
      renderDetail(detail);
    }
    notice();
  } catch (error) {
    if (generation === state.generation) notice(error.message, true);
  }
}

$("connect").addEventListener("submit", async (event) => {
  event.preventDefault();
  const generation = ++state.generation;
  state.token = $("token").value;
  $("token").value = "";
  notice("Connecting to the local registry…");
  try {
    const data = await api("/v1/dashboard/agents");
    if (generation !== state.generation) return;
    if (!data.agents.length) throw new Error("No agents are in this account’s scope.");
    const agent = data.agents[0].agent_id;
    applyMode(false);
    renderInventory(data.agents, agent);
    await loadLive(agent);
  } catch (error) {
    if (generation === state.generation) {
      state.token = "";
      notice(error.message, true);
    }
  }
});

$("scenarios").addEventListener("change", loadDemo);
$("demo-return").addEventListener("click", loadDemo);
$("agents").addEventListener("change", () => loadLive($("agents").value));
$("assessments").addEventListener("change", () => loadLive(state.agent, $("assessments").value));

$("review-action").addEventListener("click", async () => {
  const id = state.detail?.assessment.assessment_id;
  if (state.demo || !id) return;
  const generation = state.generation;
  $("review-action").disabled = true;
  notice("Running advisory review…");
  try {
    const review = await api("/v1/advisory/reviews", { method: "POST", body: { assessment_id: id } });
    if (generation === state.generation) {
      renderDetail({ ...state.detail, reviews: [review, ...state.detail.reviews] });
      notice();
    }
  } catch (error) {
    if (generation === state.generation) notice(error.message, true);
  } finally {
    $("review-action").disabled = false;
  }
});

$("approval-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const id = state.detail?.assessment.assessment_id;
  if (state.demo || !id) return;
  const generation = state.generation;
  const submit = event.submitter;
  submit.disabled = true;
  try {
    await api("/v1/governance/assessments/" + encodeURIComponent(id) + "/decisions", {
      method: "POST", body: {
        role: $("approval-role").value, decision: $("decision").value, rationale: $("rationale").value,
      },
    });
    if (generation === state.generation) {
      $("rationale").value = "";
      await loadLive(state.agent, id);
    }
  } catch (error) {
    if (generation === state.generation) notice(error.message, true);
  } finally {
    submit.disabled = false;
  }
});

$("audit-more").addEventListener("click", async () => {
  const generation = state.generation;
  const button = $("audit-more");
  button.disabled = true;
  try {
    const last = state.audit.at(-1)?.id || 0;
    const result = await api("/v1/governance/agents/" + encodeURIComponent(state.agent) + "/audit?after_id=" + last);
    if (generation !== state.generation) return;
    renderAudit([...state.audit, ...result.events]);
    button.hidden = result.events.length < 100;
  } catch (error) {
    if (generation === state.generation) notice(error.message, true);
  } finally {
    button.disabled = false;
  }
});

loadDemo();
