
(() => {
  if (window.__phishingAnalyzerInstalled) return;
  window.__phishingAnalyzerInstalled = true;

  function createInterface() {
    if (document.getElementById("pea-launch")) return;

    const button = document.createElement("button");
    button.id = "pea-launch";
    button.textContent = "Analyze Email";

    const panel = document.createElement("section");
    panel.id = "pea-panel";
    panel.hidden = true;
    panel.innerHTML = `
      <div class="pea-header">
        <strong>Phishing Email Analyzer</strong>
        <button id="pea-close" aria-label="Close">×</button>
      </div>
      <p id="pea-status">Open an email, then analyze it.</p>
      <div id="pea-result" hidden>
        <div class="pea-score"></div>
        <div class="pea-level"></div>
        <h4>Findings</h4>
        <ul class="pea-findings"></ul>
        <p class="pea-note">
          This is a heuristic estimate, not a guarantee of safety.
        </p>
      </div>
    `;

    document.body.append(button, panel);

    button.addEventListener("click", () => {
      panel.hidden = !panel.hidden;
      if (!panel.hidden) analyzeCurrentEmail();
    });

    panel.querySelector("#pea-close").addEventListener("click", () => {
      panel.hidden = true;
    });
  }

  function analyzeCurrentEmail() {
    const status = document.querySelector("#pea-status");
    const result = document.querySelector("#pea-result");

    const messageBodies = [
      ...document.querySelectorAll(".a3s")
    ].filter(element => element.getClientRects().length > 0);

    const bodyElement = messageBodies[messageBodies.length - 1];

    if (!bodyElement) {
      status.textContent =
        "Open an email message first, then click Analyze Email.";
      result.hidden = true;
      return;
    }

    const subject =
      document.querySelector(".hP")?.innerText || "";

    const senderElement = [
      ...document.querySelectorAll(".gD")
    ].filter(element => element.getClientRects().length > 0).pop();

    const sender =
      senderElement?.getAttribute("email") || "";

    const body = bodyElement.innerText || "";

    const links = [...bodyElement.querySelectorAll("a[href]")].map(a => ({
      href: a.href,
      text: a.innerText
    }));

    const analysis =
      window.PhishingAnalyzer.analyze(subject, sender, body, links);

    status.textContent = "Analysis complete";
    result.hidden = false;

    result.querySelector(".pea-score").textContent =
      `${analysis.score}/100`;

    result.querySelector(".pea-level").textContent =
      analysis.level;

    const list = result.querySelector(".pea-findings");
    list.replaceChildren();

    analysis.findings.forEach(finding => {
      const item = document.createElement("li");
      item.textContent = finding;
      list.appendChild(item);
    });
  }

  createInterface();

  const observer = new MutationObserver(() => {
    createInterface();
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
})();
