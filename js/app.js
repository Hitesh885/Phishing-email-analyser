/* =========================================================================
   app.js  —  the interface layer
   ------------------------------------------------------------------------
   This file connects the buttons and the on-screen layout to the analysis
   engine in analyzer.js. It only touches the page; it never touches the
   network. Everything the visitor pastes stays in this browser tab.

   Exposed globally as: window.AppUI
   ========================================================================= */
(function () {
  "use strict";

  var HP = window.HeaderParser;
  var Analyzer = window.Analyzer;
  var Samples = window.Samples || [];

  // Circumference of the gauge circle (radius 84): 2 * PI * r
  var GAUGE_CIRCUMFERENCE = 2 * Math.PI * 84;

  /* ---------------------------------------------------------------- */
  /*  Tiny DOM helpers                                                 */
  /* ---------------------------------------------------------------- */
  function el(id) { return document.getElementById(id); }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  var els = {
    input: el("emailInput"),
    analyseBtn: el("analyseBtn"),
    clearBtn: el("clearBtn"),
    charCount: el("charCount"),
    headerDetect: el("headerDetect"),
    sampleButtons: el("sampleButtons"),
    emptyState: el("emptyState"),
    resultsContent: el("resultsContent"),
    gauge: el("gauge"),
    gaugeProgress: el("gaugeProgress"),
    scoreValue: el("scoreValue"),
    gaugeLabel: el("gaugeLabel"),
    verdictBadge: el("verdictBadge"),
    verdictText: el("verdictText"),
    verdictMeta: el("verdictMeta"),
    hitCount: el("hitCount"),
    indicators: el("indicators"),
    recommendations: el("recommendations"),
    scoringBreakdown: el("scoringBreakdown")
  };

  /* ---------------------------------------------------------------- */
  /*  Sample buttons                                                   */
  /* ---------------------------------------------------------------- */
  function buildSampleButtons() {
    if (!els.sampleButtons) return;
    els.sampleButtons.innerHTML = "";

    Samples.forEach(function (sample) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "sample-btn";
      btn.setAttribute("title", sample.description || "");
      btn.innerHTML = escapeHtml(sample.name) +
        (sample.tag ? ' <span class="sb-tag">' + escapeHtml(sample.tag) + "</span>" : "");

      btn.addEventListener("click", function () {
        els.input.value = sample.text;
        updateInputMeta();
        runAnalysis();
        els.input.scrollTop = 0;
      });

      els.sampleButtons.appendChild(btn);
    });
  }

  /* ---------------------------------------------------------------- */
  /*  Live input feedback (character count + header detection)         */
  /* ---------------------------------------------------------------- */
  function updateInputMeta() {
    var text = els.input.value || "";
    els.charCount.textContent = text.length.toLocaleString() + (text.length === 1 ? " character" : " characters");

    if (!text.trim()) {
      els.headerDetect.textContent = "No headers detected";
      els.headerDetect.className = "meta-item meta-muted";
      return;
    }

    var split = HP.splitHeadersAndBody(text);
    if (split.hasHeaders) {
      els.headerDetect.textContent = "Headers detected - SPF / DKIM / DMARC will be checked";
      els.headerDetect.className = "meta-item meta-detected";
    } else {
      els.headerDetect.textContent = "No headers detected (body-only analysis)";
      els.headerDetect.className = "meta-item meta-muted";
    }
  }

  /* ---------------------------------------------------------------- */
  /*  Recommendations                                                  */
  /* ---------------------------------------------------------------- */
  var BASE_RECOMMENDATIONS = [
    "Do not click any links or open any attachments in a message you were not expecting.",
    "Never reply with passwords, one-time codes, card numbers or bank details.",
    "Verify the request independently: visit the organisation's official website or app, or call a number you already trust \u2014 never one given in the email.",
    "If this reached a work account, report it to your IT or security team."
  ];

  function buildRecommendations(result) {
    var recs = [];
    var seen = {};

    function add(text) {
      var key = text.toLowerCase();
      if (seen[key]) return;
      seen[key] = true;
      recs.push(text);
    }

    // Specific advice from the most serious warning signs we found.
    var serious = result.hits.filter(function (h) { return h.weight > 0; });
    for (var i = 0; i < serious.length && recs.length < 4; i++) {
      add(serious[i].advice);
    }

    // Always-useful baseline advice.
    for (var b = 0; b < BASE_RECOMMENDATIONS.length && recs.length < 7; b++) {
      add(BASE_RECOMMENDATIONS[b]);
    }

    if (result.score >= 25) {
      add("If you already clicked a link or replied: change any affected passwords immediately, turn on multi-factor authentication, and tell your IT or security team straight away.");
    }

    return recs.slice(0, 8);
  }

  /* ---------------------------------------------------------------- */
  /*  Rendering the results                                            */
  /* ---------------------------------------------------------------- */
  function severityWord(sev) {
    if (sev === "high") return "Serious";
    if (sev === "medium") return "Moderate";
    if (sev === "low") return "Minor";
    return "Note";
  }

  function renderIndicators(hits) {
    if (!hits.length) {
      els.indicators.innerHTML =
        '<div class="indicator sev-info">' +
          '<div class="ind-head"><div>' +
            '<span class="ind-cat">Result</span>' +
            '<p class="ind-title">No warning signs from our checklist were found</p>' +
          "</div></div>" +
          '<p class="ind-explain">That is reassuring, but remember this tool only looks for known patterns. ' +
          "A message can still be malicious, so keep verifying anything unexpected.</p>" +
        "</div>";
      return;
    }

    var html = "";
    hits.forEach(function (hit) {
      var pointsText = hit.weight > 0 ? "+" + hit.weight + " pts" : "info";
      var pointsClass = hit.weight > 0 ? "ind-points" : "ind-points zero";

      var evidenceHtml = "";
      if (hit.evidence && hit.evidence.length) {
        evidenceHtml =
          '<div class="ind-evidence"><span class="ev-label">Evidence found in the email</span>' +
          hit.evidence.map(function (e) { return escapeHtml(e); }).join("<br>") +
          "</div>";
      }

      html +=
        '<div class="indicator sev-' + hit.severity + '">' +
          '<div class="ind-head">' +
            "<div>" +
              '<span class="ind-cat">' + escapeHtml(hit.category) + " &middot; " + severityWord(hit.severity) + "</span>" +
              '<p class="ind-title">' + escapeHtml(hit.label) + "</p>" +
            "</div>" +
            '<span class="' + pointsClass + '">' + pointsText + "</span>" +
          "</div>" +
          '<p class="ind-explain">' + escapeHtml(hit.explain) + "</p>" +
          evidenceHtml +
          '<div class="ind-advice"><span class="arrow">&#8594;</span><span>' + escapeHtml(hit.advice) + "</span></div>" +
        "</div>";
    });

    els.indicators.innerHTML = html;
  }

  function renderScoring(result) {
    var scored = result.hits.filter(function (h) { return h.weight > 0; });
    var html = "";

    if (!scored.length) {
      html += '<li><span>No scoring indicators triggered</span><span class="sl-points">+0</span></li>';
    } else {
      scored.forEach(function (h) {
        html += "<li><span>" + escapeHtml(h.label) + "</span>" +
                '<span class="sl-points">+' + h.weight + "</span></li>";
      });
    }

    html += '<li class="sl-total"><span>Total' +
      (result.capped ? " (capped at the maximum of 100)" : "") +
      "</span><span class=\"sl-points\">" + result.score + " / 100</span></li>";

    els.scoringBreakdown.innerHTML = html;
  }

  function animateScore(target, level) {
    els.gauge.setAttribute("data-level", level);
    els.gaugeProgress.style.strokeDashoffset = GAUGE_CIRCUMFERENCE;

    // Force a reflow so the transition runs from the "empty" state.
    void els.gaugeProgress.getBoundingClientRect();

    var offset = GAUGE_CIRCUMFERENCE * (1 - target / 100);
    els.gaugeProgress.style.strokeDashoffset = offset;

    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotion) { els.scoreValue.textContent = target; return; }

    var start = Date.now();
    var duration = 900;
    (function tick() {
      var t = Math.min(1, (Date.now() - start) / duration);
      var eased = 1 - Math.pow(1 - t, 3);
      els.scoreValue.textContent = Math.round(target * eased);
      if (t < 1) requestAnimationFrame(tick);
      else els.scoreValue.textContent = target;
    })();
  }

  function renderResult(result) {
    els.emptyState.hidden = true;
    els.resultsContent.hidden = false;

    // Gauge + verdict
    animateScore(result.score, result.level);
    els.gaugeLabel.textContent = result.levelLabel;

    els.verdictBadge.textContent = result.levelLabel;
    els.verdictBadge.setAttribute("data-level", result.level);
    els.verdictText.textContent = result.summary;

    var metaBits = [];
    var scoredCount = result.hits.filter(function (h) { return h.weight > 0; }).length;
    metaBits.push(scoredCount + (scoredCount === 1 ? " scoring warning sign" : " scoring warning signs"));
    if (result.counts.high) metaBits.push(result.counts.high + " serious");
    if (result.counts.medium) metaBits.push(result.counts.medium + " moderate");
    metaBits.push(result.meta.hasHeaders
      ? "headers analysed"
      : "add the email headers for an SPF / DKIM / DMARC check");
    els.verdictMeta.textContent = metaBits.join(" \u00b7 ");

    // Warning signs
    els.hitCount.textContent = result.hits.length + " found";
    renderIndicators(result.hits);

    // Recommendations
    var recs = buildRecommendations(result);
    els.recommendations.innerHTML = recs.map(function (r, i) {
      return '<div class="rec"><span class="rec-num">' + (i + 1) + "</span><span>" + escapeHtml(r) + "</span></div>";
    }).join("");

    // Scoring breakdown
    renderScoring(result);
  }

  function showError(message) {
    els.resultsContent.hidden = true;
    els.emptyState.hidden = false;
    els.emptyState.innerHTML =
      '<div class="empty-icon" aria-hidden="true">' +
        '<svg viewBox="0 0 24 24" width="46" height="46"><path fill="currentColor" d="M12 2 1 21h22L12 2Zm0 5 7 12H5l7-12Zm-1 4v4h2v-4h-2Zm0 5v2h2v-2h-2Z"/></svg>' +
      "</div><h3>Nothing to analyse yet</h3><p>" + escapeHtml(message) + "</p>";
  }

  /* ---------------------------------------------------------------- */
  /*  Actions                                                          */
  /* ---------------------------------------------------------------- */
  function runAnalysis() {
    var text = els.input.value || "";
    var result = Analyzer.analyse(text);

    if (result.error) {
      showError(result.error);
      return;
    }
    renderResult(result);

    // Bring the results into view on small screens where they sit below.
    if (window.innerWidth <= 940) {
      els.resultsContent.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  // The original "No analysis yet" panel, saved so it can be restored after an
  // error message has replaced it.
  var originalEmptyHtml = "";

  function clearAll() {
    els.input.value = "";
    updateInputMeta();
    els.resultsContent.hidden = true;
    els.emptyState.hidden = false;
    if (originalEmptyHtml) els.emptyState.innerHTML = originalEmptyHtml;
    els.input.focus();
  }

  /* ---------------------------------------------------------------- */
  /*  Start up                                                         */
  /* ---------------------------------------------------------------- */
  function init() {
    originalEmptyHtml = els.emptyState.innerHTML;
    buildSampleButtons();
    updateInputMeta();

    els.input.addEventListener("input", updateInputMeta);
    els.analyseBtn.addEventListener("click", runAnalysis);
    els.clearBtn.addEventListener("click", clearAll);

    // Ctrl/Cmd + Enter runs the analysis from inside the text area.
    els.input.addEventListener("keydown", function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runAnalysis();
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.AppUI = { runAnalysis: runAnalysis, clear: clearAll };
})();
