"use strict";

const API_URL = (window.POLICYLENS_CONFIG || {}).API_URL || "/analyze";

const $ = (id) => document.getElementById(id);

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function setStatus(msg, isError) {
  const el = $("status");
  el.textContent = msg || "";
  el.classList.toggle("error", !!isError);
}

// --- Sample chips: one click fills the box AND analyzes -------------------

function renderSamples() {
  const wrap = $("samples");
  (window.POLICYLENS_SAMPLES || []).forEach((sample) => {
    const chip = document.createElement("button");
    chip.className = "chip";
    chip.textContent = sample.name;
    chip.title = sample.blurb;
    chip.addEventListener("click", () => {
      $("policy-input").value = JSON.stringify(sample.policy, null, 2);
      $("policy-list").hidden = true;
      analyze();
    });
    wrap.appendChild(chip);
  });
}

// --- File upload (inline) --------------------------------------------------

$("file-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    let parsed;
    try {
      parsed = JSON.parse(reader.result);
    } catch (err) {
      setStatus("That file is not valid JSON.", true);
      return;
    }
    if (Array.isArray(parsed)) {
      // A fetch_policies.py export: let the user pick one policy.
      renderPolicyList(parsed);
    } else {
      $("policy-list").hidden = true;
      $("policy-input").value = JSON.stringify(parsed, null, 2);
      analyze();
    }
  };
  reader.readAsText(file);
  e.target.value = ""; // allow re-uploading the same file
});

function renderPolicyList(entries) {
  const list = $("policy-list");
  list.innerHTML = "";
  const usable = entries.filter((e) => e && e.policy_document);
  if (usable.length === 0) {
    setStatus("No policies found in that file.", true);
    list.hidden = true;
    return;
  }
  usable.forEach((entry) => {
    const item = document.createElement("div");
    item.className = "plitem";
    item.innerHTML =
      "<div><strong>" +
      escapeHtml(entry.policy_name || "(unnamed)") +
      "</strong><div class='pmeta'>role: " +
      escapeHtml(entry.role_name || "?") +
      "</div></div><span class='badge'>" +
      escapeHtml(entry.policy_type || "policy") +
      "</span>";
    item.addEventListener("click", () => {
      document.querySelectorAll(".plitem").forEach((n) => n.classList.remove("selected"));
      item.classList.add("selected");
      $("policy-input").value = JSON.stringify(entry.policy_document, null, 2);
      analyze();
    });
    list.appendChild(item);
  });
  list.hidden = false;
  setStatus("Pick a policy to review.");
}

// --- Analyze ---------------------------------------------------------------

$("analyze-btn").addEventListener("click", analyze);

async function analyze() {
  const raw = $("policy-input").value.trim();
  if (!raw) {
    setStatus("Paste a policy or pick an example first.", true);
    return;
  }
  const btn = $("analyze-btn");
  btn.disabled = true;
  setStatus("Analyzing...");
  $("results").hidden = true;

  // Send parsed JSON when possible; otherwise the raw text so the backend
  // returns a clean parse error.
  let payload = raw;
  try {
    payload = JSON.parse(raw);
  } catch (e) {
    /* leave as string */
  }

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ policy: payload }),
    });
    const data = await res.json();
    if (!data.ok) {
      setStatus(data.error || "Analysis failed.", true);
      return;
    }
    renderResults(data, raw);
    setStatus("");
    $("results").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    setStatus("Could not reach the analysis service: " + err.message, true);
  } finally {
    btn.disabled = false;
  }
}

// --- Results ---------------------------------------------------------------

function renderResults(data, originalRaw) {
  const ai = data.ai;
  const aiByRule = {};
  if (ai && Array.isArray(ai.findings)) {
    ai.findings.forEach((f) => {
      if (!aiByRule[f.rule_id]) aiByRule[f.rule_id] = f;
    });
  }

  const count = data.findings.length;
  const summary = $("summary");
  summary.classList.toggle("degraded", !!data.degraded);
  summary.classList.toggle("clean", count === 0 && !data.degraded);
  if (data.degraded) {
    summary.innerHTML =
      "<strong>AI step unavailable.</strong> Showing the deterministic findings only. " +
      escapeHtml(data.degraded_reason || "");
  } else if (count === 0) {
    summary.textContent = "No issues found. This policy looks well scoped.";
  } else if (ai && ai.summary) {
    summary.textContent = ai.summary;
  } else {
    summary.textContent = count + " issue" + (count === 1 ? "" : "s") + " found.";
  }

  $("findings-title").textContent =
    count === 0 ? "Findings" : "Findings (" + count + ")";

  const wrap = $("findings");
  wrap.innerHTML = "";
  if (count === 0) {
    wrap.innerHTML =
      "<div class='finding LOW'><div class='detail'>Nothing flagged.</div></div>";
  }
  data.findings.forEach((f) => {
    const ai1 = aiByRule[f.rule_id];
    const stmt = f.statement_index < 0 ? "document" : "statement " + f.statement_index;
    const el = document.createElement("div");
    el.className = "finding " + f.severity;
    let html =
      "<div class='frow'><span class='sev " +
      f.severity +
      "'>" +
      f.severity +
      "</span><span class='rule-id'>" +
      escapeHtml(f.rule_id) +
      "</span><span class='stmt'>" +
      stmt +
      "</span></div><div class='detail'>" +
      escapeHtml(f.detail) +
      "</div>";
    if (ai1) {
      if (ai1.explanation)
        html += "<div class='explain'>" + escapeHtml(ai1.explanation) + "</div>";
      if (ai1.business_impact)
        html += "<div class='impact'><b>Impact:</b> " + escapeHtml(ai1.business_impact) + "</div>";
      if (ai1.fix) html += "<div class='fix'><b>Fix:</b> " + escapeHtml(ai1.fix) + "</div>";
    }
    el.innerHTML = html;
    wrap.appendChild(el);
  });

  const block = $("rewrite-block");
  if (ai && ai.rewrite_valid && ai.rewritten_policy) {
    block.hidden = false;
    renderDiff(originalRaw, ai.rewritten_policy);
  } else {
    block.hidden = true;
  }

  $("results").hidden = false;
}

function toPretty(policy) {
  if (typeof policy === "string") {
    try {
      return JSON.stringify(JSON.parse(policy), null, 2);
    } catch (e) {
      return policy;
    }
  }
  return JSON.stringify(policy, null, 2);
}

// LCS line diff: unchanged lines stay plain, changes are highlighted.
function diffMarks(aLines, bLines) {
  const n = aLines.length,
    m = bLines.length;
  const dp = [];
  for (let i = 0; i <= n; i++) dp.push(new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] =
        aLines[i] === bLines[j]
          ? dp[i + 1][j + 1] + 1
          : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const aMark = new Array(n).fill(false),
    bMark = new Array(m).fill(false);
  let i = 0,
    j = 0;
  while (i < n && j < m) {
    if (aLines[i] === bLines[j]) {
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      aMark[i++] = true;
    } else {
      bMark[j++] = true;
    }
  }
  while (i < n) aMark[i++] = true;
  while (j < m) bMark[j++] = true;
  return { aMark, bMark };
}

function renderLines(lines, marks, cls) {
  return lines
    .map(
      (line, idx) =>
        "<span class='ln " +
        (marks[idx] ? cls : "") +
        "'>" +
        escapeHtml(line || " ") +
        "</span>"
    )
    .join("\n");
}

function renderDiff(original, rewritten) {
  const aLines = toPretty(original).split("\n");
  const bLines = toPretty(rewritten).split("\n");
  const { aMark, bMark } = diffMarks(aLines, bLines);
  $("diff-original").innerHTML = renderLines(aLines, aMark, "del");
  $("diff-rewritten").innerHTML = renderLines(bLines, bMark, "add");
}

renderSamples();
