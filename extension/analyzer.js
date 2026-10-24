
window.PhishingAnalyzer = {
  analyze(subject, sender, body, links) {
    let score = 0;
    const findings = [];

    const text = `${subject} ${body}`.toLowerCase();

    const urgentWords = [
      "urgent", "immediately", "act now",
      "account suspended", "verify your account"
    ];

    if (urgentWords.some(word => text.includes(word))) {
      score += 20;
      findings.push("Urgent or threatening language");
    }

    const sensitiveWords = [
      "password", "otp", "bank details",
      "credit card", "login credentials"
    ];

    if (sensitiveWords.some(word => text.includes(word))) {
      score += 20;
      findings.push("Request for sensitive information");
    }

    if (links.length > 0) {
      const suspiciousLinks = links.filter(link => {
        try {
          const url = new URL(link.href);
          return (
            url.protocol !== "https:" ||
            /@|xn--/i.test(url.hostname) ||
            /^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)
          );
        } catch {
          return true;
        }
      });

      if (suspiciousLinks.length > 0) {
        score += 30;
        findings.push("Potentially suspicious link destination");
      }
    }

    if (!sender || !sender.includes("@")) {
      findings.push("Sender address could not be verified");
    }

    score = Math.min(score, 100);

    let level = "Low risk";
    if (score >= 60) {
      level = "High risk";
    } else if (score >= 30) {
      level = "Suspicious";
    }

    if (findings.length === 0) {
      findings.push("No obvious warning signs detected");
    }

    return { score, level, findings };
  }
};
