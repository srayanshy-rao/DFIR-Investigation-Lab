const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
let allCases = [];

async function api(url, opt) {
  const r = await fetch(url, opt);
  if (!r.ok) throw new Error(await r.text());
  return r.json();
}

function riskClass(v) {
  return String(v || "LOW").toLowerCase();
}

function renderCases(cases) {
  const q = $("#case-search").value.trim().toLowerCase();
  const level = $("#risk-filter").value;
  const filtered = cases.filter(c => {
    const hay = [c.id, c.title, c.investigator, c.evidence?.filename, c.evidence?.detected_type].join(" ").toLowerCase();
    return (!q || hay.includes(q)) && (level === "ALL" || c.risk?.level === level);
  });

  $("#case-list").innerHTML = filtered.length ? filtered.map(c => `
    <article class="case clickable" data-case="${esc(c.id)}">
      <div class="case-top">
        <div><b>${esc(c.id)}</b> — ${esc(c.title)}</div>
        <span class="badge ${esc(c.risk?.level || "LOW")}">${esc(c.risk?.level || "LOW")} ${c.risk?.score ?? 0}/100</span>
      </div>
      <small>${esc(c.evidence?.filename || "")} • ${esc(c.evidence?.detected_type || "")} • ${esc(c.date || "")}</small>
      <p>${esc(c.summary || "")}</p>
      <button class="case-action" data-open="${esc(c.id)}">Open case details →</button>
    </article>
  `).join("") : "No investigations match the current filters.";

  document.querySelectorAll("[data-open]").forEach(btn => {
    btn.addEventListener("click", e => {
      e.stopPropagation();
      openCase(btn.dataset.open);
    });
  });

  document.querySelectorAll("[data-case]").forEach(card => {
    card.addEventListener("click", () => openCase(card.dataset.case));
  });
}

function renderTimeline(events) {
  $("#timeline-list").innerHTML = events.length ? events.map(e => `
    <div class="timeline">
      <b>${esc(e.event)}</b>
      <small>${esc(e.time)} • ${esc(e.case_id)}</small>
      <div>${esc(e.detail)}</div>
    </div>
  `).join("") : "No timeline events yet.";
}

function updateCaseSelect(cases) {
  const current = $("#verify-case").value;
  $("#verify-case").innerHTML = `<option value="">Select investigation case</option>` +
    cases.map(c => `<option value="${esc(c.id)}">${esc(c.id)} — ${esc(c.evidence?.filename || c.title)}</option>`).join("");
  if (cases.some(c => c.id === current)) $("#verify-case").value = current;
}

async function load() {
  try {
    const [h, c, t] = await Promise.all([
      api("/api/health"),
      api("/api/cases"),
      api("/api/timeline")
    ]);

    allCases = c;
    $("#status").textContent = "● API ONLINE v" + h.version;
    $("#status").style.color = "#2bd6a1";
    $("#stat-api").textContent = "ONLINE";
    $("#stat-cases").textContent = c.length;
    $("#stat-high").textContent = c.filter(x => x.risk?.level === "HIGH").length;
    $("#stat-entropy").textContent = c[0]?.evidence?.entropy ?? "—";

    renderCases(c);
    renderTimeline(t);
    updateCaseSelect(c);
  } catch (e) {
    $("#status").textContent = "● API OFFLINE";
    $("#stat-api").textContent = "OFFLINE";
  }
}

async function openCase(caseId) {
  $("#case-modal").classList.remove("hidden");
  $("#case-detail").textContent = "Loading case details…";

  try {
    const c = await api("/api/cases/" + encodeURIComponent(caseId));
    const e = c.evidence;
    const r = c.risk;

    $("#case-detail").innerHTML = `
      <p class="eyebrow">CASE DETAILS</p>
      <h2>${esc(c.id)}</h2>
      <p class="muted">${esc(c.title)}</p>

      <div class="detail-grid">
        <div><small>INVESTIGATOR</small><b>${esc(c.investigator)}</b></div>
        <div><small>ANALYSIS TIME</small><b>${esc(c.date)}</b></div>
        <div><small>RISK SCORE</small><b class="${riskClass(r.level)}">${esc(r.level)} ${esc(r.score)}/100</b></div>
        <div><small>EXTENSION MATCH</small><b>${r.extension_mismatch ? "FAILED" : "VALID"}</b></div>
      </div>

      <h3>Evidence Metadata</h3>
      <div class="detail-grid">
        <div><small>FILE</small><b>${esc(e.filename)}</b></div>
        <div><small>SIZE</small><b>${esc(e.size)} bytes</b></div>
        <div><small>CLAIMED EXTENSION</small><b>${esc(e.extension || "None")}</b></div>
        <div><small>DETECTED TYPE</small><b>${esc(e.detected_type)}</b></div>
        <div><small>MAGIC BYTES</small><code>${esc(e.magic_bytes)}</code></div>
        <div><small>ENTROPY</small><b>${esc(e.entropy)} / 8.0</b></div>
      </div>

      <h3>Cryptographic Hashes</h3>
      <div class="hash-box"><small>MD5</small><code>${esc(e.md5)}</code></div>
      <div class="hash-box"><small>SHA-256</small><code>${esc(e.sha256)}</code></div>

      <h3>Forensic Findings</h3>
      <ul class="findings">${r.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>

      <a class="report-link" href="/api/reports/${encodeURIComponent(c.id)}" target="_blank">Download full investigation report →</a>
    `;
  } catch (e) {
    $("#case-detail").textContent = "Unable to load case: " + e.message;
  }
}

const dz = $("#dropzone");
const file = $("#evidence");

file.addEventListener("change", () => $("#file-name").textContent = file.files[0]?.name || "No file selected");

["dragenter", "dragover"].forEach(x => dz.addEventListener(x, e => {
  e.preventDefault();
  dz.classList.add("drag");
}));

["dragleave", "drop"].forEach(x => dz.addEventListener(x, e => {
  e.preventDefault();
  dz.classList.remove("drag");
}));

dz.addEventListener("drop", e => {
  file.files = e.dataTransfer.files;
  $("#file-name").textContent = file.files[0]?.name || "No file selected";
});

$("#investigation-form").addEventListener("submit", async e => {
  e.preventDefault();
  if (!file.files[0]) return;

  const fd = new FormData();
  fd.append("file", file.files[0]);
  fd.append("title", $("#title").value);
  fd.append("investigator", $("#investigator").value);

  $("#submit").disabled = true;
  $("#scan").classList.remove("hidden");
  $("#result").classList.add("hidden");

  try {
    const c = await api("/api/investigate", {method: "POST", body: fd});
    const ev = c.evidence;
    const r = c.risk;

    $("#result").innerHTML = `
      <div class="result-grid">
        <div class="metric"><small>CASE ID</small>${esc(c.id)}</div>
        <div class="metric"><small>DETECTED TYPE</small>${esc(ev.detected_type)}</div>
        <div class="metric"><small>MAGIC BYTES</small><code>${esc(ev.magic_bytes)}</code></div>
        <div class="metric"><small>ENTROPY</small>${esc(ev.entropy)} / 8.0</div>
        <div class="metric"><small>MD5</small><code>${esc(ev.md5)}</code></div>
        <div class="metric"><small>SHA-256</small><code>${esc(ev.sha256)}</code></div>
      </div>
      <div class="risk ${riskClass(r.level)}">${esc(r.level)} RISK — ${esc(r.score)}/100</div>
      <div class="mismatch ${r.extension_mismatch ? "danger" : "safe"}">
        ${r.extension_mismatch ? "⚠ EXTENSION / SIGNATURE MISMATCH DETECTED" : "✓ EXTENSION / SIGNATURE CHECK PASSED"}
      </div>
      <ul class="findings">${r.reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
      <button class="case-action" id="open-new-case">Open complete case details →</button>
    `;

    $("#result").classList.remove("hidden");
    $("#report").href = c.report_url;
    $("#report").classList.remove("hidden");
    $("#open-new-case").addEventListener("click", () => openCase(c.id));
    await load();
  } catch (err) {
    $("#result").textContent = "Analysis failed: " + err.message;
    $("#result").classList.remove("hidden");
  } finally {
    $("#scan").classList.add("hidden");
    $("#submit").disabled = false;
  }
});

$("#verify-form").addEventListener("submit", async e => {
  e.preventDefault();
  const caseId = $("#verify-case").value;
  const expected = $("#expected-hash").value.trim();
  const box = $("#verify-result");

  if (!caseId || !expected) {
    box.textContent = "Select a case and provide an expected hash.";
    box.className = "verify-result failure";
    return;
  }

  try {
   const result = await api(
    "/api/cases/" +
    encodeURIComponent(caseId) +
    "/verify?expected_hash=" +
    encodeURIComponent(expected),
    {
        method: "POST"
    }
);

    box.innerHTML = `
      <b>${result.matched ? "✓ HASH MATCHED" : "✗ HASH MISMATCH"}</b>
      <p>${esc(result.message)}</p>
      <small>${esc(result.algorithm)} • Actual: <code>${esc(result.actual_hash)}</code></small>
    `;
    box.className = "verify-result " + (result.matched ? "success" : "failure");
    await load();
  } catch (err) {
    box.textContent = "Verification failed: " + err.message;
    box.className = "verify-result failure";
  }
});

$("#case-search").addEventListener("input", () => renderCases(allCases));
$("#risk-filter").addEventListener("change", () => renderCases(allCases));
$("#refresh").addEventListener("click", load);
$("#close-modal").addEventListener("click", () => $("#case-modal").classList.add("hidden"));
$("#case-modal").addEventListener("click", e => {
  if (e.target === $("#case-modal")) $("#case-modal").classList.add("hidden");
});

load();
