/* =========================================================================
   analyzer.js  —  THE BRAIN of the Phishing Email Analyser
   ------------------------------------------------------------------------
   This file contains every "warning sign" check and the transparent scoring
   system. It runs entirely in the browser. It does NOT talk to the network.

   How it works, in plain English:
     • The email text is split into a body part (and optionally a header part).
     • Each RULE below looks for one kind of warning sign using a pattern.
     • If a rule finds its pattern, it adds a FIXED number of points and
       records the matched text as evidence.
     • The score is simply the sum of those points, capped at 100.

   Every rule carries its own explanation and advice, so the interface can tell
   the visitor exactly WHY the score is what it is.

   Exposed globally as: window.Analyzer  (window.Analyzer.analyse)
   ========================================================================= */
(function () {
  "use strict";

  var HP = window.HeaderParser;

  /* ---------------------------------------------------------------- */
  /*  Lookup data used by the rules                                    */
  /* ---------------------------------------------------------------- */

  // Well-known URL shorteners (they hide the real destination).
  var SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "bit.do",
    "shorte.st", "adf.ly", "s.id", "t.ly", "v.gd", "lnkd.in", "db.tt"
  ];

  // Top-level domains that are cheap/free and heavily abused in phishing.
  var SUSPICIOUS_TLDS = [
    ".zip", ".mov", ".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga",
    ".click", ".country", ".work", ".loan", ".win", ".review", ".buzz", ".rest",
    ".quest", ".cyou", ".monster", ".sbs", ".cfd", ".icu", ".men"
  ];

  // File types that can run code or install software = dangerous attachments.
  // Note: the legacy ".com" program type is deliberately NOT listed, because it
  // would clash with ordinary domain names such as "example.com".
  var EXEC_EXTS = [
    "exe", "scr", "pif", "bat", "cmd", "msi", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "ps1", "psm1", "jar", "lnk", "reg", "cpl", "gadget",
    "application", "inf"
  ];

  // Archive / disc-image types often used to smuggle an executable past filters.
  var ARCHIVE_EXTS = ["zip", "rar", "7z", "iso", "img", "cab", "gz", "tar", "ace"];

  // Brands commonly impersonated by phishing campaigns.
  var BRANDS = [
    "microsoft", "office365", "office365", "outlook", "onedrive", "sharepoint",
    "apple", "icloud", "google", "gmail", "amazon", "paypal", "netflix",
    "docusign", "dropbox", "adobe", "dhl", "fedex", "ups", "royalmail",
    "hsbc", "barclays", "lloyds", "nationwide", "santander", "hdfc", "icici",
    "sbi", "axisbank", "chase", "wellsfargo", "citibank", "coinbase", "binance"
  ];

  // Document types that should NOT arrive as a naked attachment in a normal
  // business email when combined with other warning signs.
  var DOC_EXTS = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv", "html", "htm"];

  /* ---------------------------------------------------------------- */
  /*  Small helper functions                                          */
  /* ---------------------------------------------------------------- */

  /** Return a de-duplicated list of up to `limit` substrings matching `re`. */
  function matchList(re, text, limit) {
    var out = [];
    var seen = {};
    var m;
    re.lastIndex = 0;
    while ((m = re.exec(text)) !== null) {
      var key = m[0].toLowerCase().trim();
      if (key === "" || seen[key]) continue;
      seen[key] = true;
      out.push(m[0].trim());
      if (out.length >= (limit || 6)) break;
      if (m.index === re.lastIndex) re.lastIndex++; // guard against zero-length
    }
    return out;
  }

  /** Parse a URL into simple parts without any external library. */
  function parseUrl(u) {
    var s = String(u || "").trim();
    var out = { raw: s, scheme: "", host: "", port: "", hasUserInfo: false, path: "" };

    var schemeMatch = s.match(/^([a-z][a-z0-9+.-]*):\/\//i);
    if (schemeMatch) {
      out.scheme = schemeMatch[1].toLowerCase();
      s = s.slice(schemeMatch[0].length);
    }

    var afterHost = s.match(/^([^\/?#]*)(.*)$/);
    var hostPart = afterHost ? afterHost[1] : s;
    out.path = afterHost ? afterHost[2] : "";

    var at = hostPart.lastIndexOf("@");
    if (at !== -1) { out.hasUserInfo = true; hostPart = hostPart.slice(at + 1); }

    var portMatch = hostPart.match(/:(\d+)$/);
    if (portMatch) { out.port = portMatch[1]; hostPart = hostPart.slice(0, -portMatch[0].length); }

    out.host = hostPart.toLowerCase();
    return out;
  }

  /** True if the host is a bare IPv4 address (e.g. 203.0.113.10). */
  function isRawIPv4(host) {
    var parts = String(host).split(".");
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
      if (!/^\d{1,3}$/.test(parts[i])) return false;
      var n = Number(parts[i]);
      if (n < 0 || n > 255) return false;
    }
    return true;
  }

  var IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;

  /* ---------------------------------------------------------------- */
  /*  THE RULES                                                        */
  /* ---------------------------------------------------------------- */
  /*  Each rule has:
        id         unique short name
        label      short headline shown to the visitor
        category   grouping shown above the headline
        weight     points added to the score when it fires (fixed!)
        severity   "high" | "medium" | "low" | "info"
        group      optional; if two rules in the same group fire, only the
                   highest-weight one counts (prevents double-counting)
        explain    plain-English "why this matters"
        advice     plain-English "what to do"
        run(ctx)   returns an array of evidence snippets, or null if no match
  */

  var RULES = [

    /* ---------- Urgency & pressure ---------- */
    {
      id: "urgency_language",
      label: "Urgency and pressure language",
      category: "Urgency & Pressure",
      weight: 10,
      severity: "medium",
      explain: "Phishing often creates panic or a deadline so you act before you think. Real organisations rarely demand instant action by email.",
      advice: "Slow down. Never act just because an email says you must act within minutes or hours.",
      run: function (ctx) {
        return matchList(/\b(urgent|urgently|immediately|right away|as soon as possible|asap|act now|act immediately|immediate action|action required|final notice|final warning|last warning|time[- ]sensitive|expires (today|soon|in \d+|within)|within \d+ (hours?|minutes?|days?)|don'?t delay|do not delay|limited time|respond immediately|verify immediately|update immediately|last chance)\b/gi, ctx.content, 6);
      }
    },

    /* ---------- Account threats ---------- */
    {
      id: "account_suspension",
      label: "Threat of account suspension or closure",
      category: "Account & Access Threats",
      weight: 15,
      severity: "high",
      explain: "Threatening to suspend, close or lock your account is a classic scare tactic designed to push you towards a fake login page.",
      advice: "Do not click links in the email. Log in to the service the normal way (type its address yourself, or use its official app) to check your account.",
      run: function (ctx) {
        return matchList(/\b(account (will be|has been|may be|is|has)\s+(?:temporarily\s+)?(suspended|closed|terminated|deactivated|locked|disabled|restricted|blocked|frozen)|suspended|deactivated|permanently closed|account closure|account will be (closed|locked|removed)|access will be (revoked|denied|terminated)|your account is (at risk|scheduled)|disable your account)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "legal_financial_threat",
      label: "Legal or financial threat",
      category: "Account & Access Threats",
      weight: 10,
      severity: "medium",
      explain: "Warnings about legal action, fines or charges are used to frighten people into complying quickly.",
      advice: "Treat threats in email with suspicion. Contact the organisation through a number or website you already trust.",
      run: function (ctx) {
        return matchList(/\b(legal action|legal proceedings|court|lawsuit|law ?suit|prosecut\w*|fine|penalt\w*|late fee|will be charged|account will be debited|debt collect\w*|bailiff)\b/gi, ctx.content, 6);
      }
    },

    /* ---------- Credential theft ---------- */
    {
      id: "password_request",
      label: "Requests a password",
      category: "Credential Theft",
      weight: 22,
      severity: "high",
      group: "password",
      explain: "No legitimate organisation ever asks for your password by email. A request for a password is one of the strongest signs of a credential-stealing attack.",
      advice: "Never send or type your password in response to an email. If you already did, change that password immediately everywhere you reused it.",
      run: function (ctx) {
        var hasPassword = /\b(password|passphrase|pass ?code)\b/i.test(ctx.content);
        var hasRequest = /\b(enter|verify|confirm|update|provide|send|reply|re-?enter|log ?in|sign ?in|click|submit|type|reset|validate)\b/i.test(ctx.content);
        if (!hasPassword || !hasRequest) return null;
        var found = matchList(/\b(password|passphrase|pass ?code)\b/gi, ctx.content, 4);
        return ["mentions: " + found.join(", "), "alongside a request to act"];
      }
    },
    {
      id: "password_mention",
      label: "Mentions a password",
      category: "Credential Theft",
      weight: 8,
      severity: "low",
      group: "password",
      explain: "Passwords are rarely mentioned in genuine email, so seeing the word is a mild warning sign on its own.",
      advice: "Be cautious. Never share a password by email, even if the request looks official.",
      run: function (ctx) {
        var found = matchList(/\b(password|passphrase|pass ?code)\b/gi, ctx.content, 4);
        return found.length ? found : null;
      }
    },
    {
      id: "mfa_code_request",
      label: "Requests an MFA / verification code",
      category: "Credential Theft",
      weight: 22,
      severity: "high",
      group: "mfa",
      explain: "One-time / MFA codes are the keys to your account. Anyone asking you to read one out or type it into a form is trying to take over your account.",
      advice: "Never share a one-time or verification code with anyone. Genuine support staff will never ask for it.",
      run: function (ctx) {
        return matchList(/\b(one[- ]?time (codes?|passwords?|passcodes?|pins?)|otp|verification codes?|security codes?|authentication codes?|auth(entication)? codes?|two[- ]?factor codes?|2fa codes?|mfa codes?|6[- ]?digit codes?|codes? we (just )?sent|code sent to your (phone|device)|sms codes?|authenticator codes?)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "credential_harvesting",
      label: "Credential-harvesting language",
      category: "Credential Theft",
      weight: 15,
      severity: "high",
      explain: "Phrases like 'verify your account' or 'log in to confirm your details' are bait that leads to a fake login page built to capture your username and password.",
      advice: "Never log in through a link in an email. Open the service directly and check there instead.",
      run: function (ctx) {
        return matchList(/\b(verify your (account|identity|information|details|email|address)|confirm your (account|identity|information|details|email)|validate your account|re[- ]?activate your account|restore your account|unlock your account|update your (account )?(information|details|profile)|sign ?in to (confirm|verify|restore|unlock)|log ?in to (confirm|verify|restore|unlock)|click here to (verify|confirm|restore|unlock|update)|re[- ]?enter your|enter your credentials|confirm your details|reactivate)\b/gi, ctx.content, 6);
      }
    },

    /* ---------- Payment fraud ---------- */
    {
      id: "payment_giftcard",
      label: "Payment or gift-card request",
      category: "Payment Fraud",
      weight: 18,
      severity: "high",
      group: "payment",
      explain: "Gift cards, cryptocurrency and wire transfers are favourite tools of fraudsters because they are hard to reverse and hard to trace.",
      advice: "Never pay with gift cards, crypto or a wire transfer because an email asked you to. Verify the request by phone with someone you know.",
      run: function (ctx) {
        return matchList(/\b(gift ?cards?|itunes cards?|google play (card|gift)s?|amazon cards?|steam (card|wallet|gift)s?|prepaid cards?|vouchers?|e-?gift ?cards?|bitcoin|btc|btc wallet|crypto(currency)?|wire transfers?|western union|money ?gram|bank transfers?|zelle|apple pay|purchase .{0,20}cards?|send .{0,15}payment)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "bank_details_change",
      label: "Request to change bank / payment details",
      category: "Payment Fraud",
      weight: 18,
      severity: "high",
      group: "bank",
      explain: "Requests to change bank details or confirm account numbers are the hallmark of business-email-compromise and invoice fraud, where payments are redirected to criminals.",
      advice: "Never change payment or bank details based on an email alone. Confirm them by calling a known, trusted contact number.",
      run: function (ctx) {
        return matchList(/\b(update your bank|change your bank|new bank account|bank account (number|details)|account number|sort code|routing number|iban|swift (code|bic)|payment details|update (your )?(billing|payment) (details|information)|direct deposit|remittance (details|account|advice)|change the (account|payment) (number|details)|standing order)\b/gi, ctx.content, 6);
      }
    },

    /* ---------- Impersonation & social engineering ---------- */
    {
      id: "impersonation_language",
      label: "Impersonation language",
      category: "Impersonation",
      weight: 10,
      severity: "medium",
      explain: "Signing off as an IT department, security team or a well-known brand is a common way to look trustworthy while pretending to be someone you are not.",
      advice: "Check the actual email address, not just the display name. Independent verification is the only reliable test.",
      run: function (ctx) {
        return matchList(/\b(it (support|department|help ?desk|service desk)|help ?desk|security team|account team|administrator|sys ?admin|from the desk of|billing department|payroll department|human resources|the (microsoft|apple|google|paypal|amazon|netflix|dhl|fedex|ups) (team|account team|support|security))\b/gi, ctx.content, 6);
      }
    },
    {
      id: "generic_greeting",
      label: "Generic, impersonal greeting",
      category: "Impersonation",
      weight: 8,
      severity: "low",
      explain: "A greeting like 'Dear Customer' instead of your real name suggests the sender does not actually know who you are \u2014 typical of bulk phishing.",
      advice: "Treat anonymous greetings with extra caution, especially in messages about money or accounts.",
      run: function (ctx) {
        return matchList(/\b(dear (customer|user|client|member|sir|madam|sir ?\/ ?madam|valued customer|account holders?|card ?holders?|friend|taxpayer|candidate|applicant|student|employee|subscriber|resident|patient)|to whom it may concern)\b/gi, ctx.content, 4);
      }
    },
    {
      id: "secrecy_request",
      label: "Requests secrecy or confidentiality",
      category: "Social Engineering",
      weight: 8,
      severity: "low",
      explain: "Asking you to keep a request secret, or to act without telling anyone, is designed to stop you checking with a colleague who might spot the fraud.",
      advice: "Secrecy in a business request is a red flag. Discuss it with a trusted colleague or manager.",
      run: function (ctx) {
        return matchList(/\b(keep this (confidential|secret|between us|quiet)|do not (tell|discuss|mention) (anyone|anybody)|don'?t tell anyone|confidential matter|between you and me|this must remain confidential|do not disclose|strictly confidential)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "unexpected_invoice",
      label: "Unexpected invoice or payment demand",
      category: "Social Engineering",
      weight: 10,
      severity: "medium",
      explain: "A surprise invoice, receipt or overdue balance is a common hook. If you were not expecting it, the attachment or link is often malicious.",
      advice: "Do not open the attachment. Check with your finance or accounts team and confirm the invoice through a known contact.",
      run: function (ctx) {
        return matchList(/\b(attached (invoices?|receipts?|statements?|purchase order)|please find (attached|the attached)|outstanding (invoices?|balance|payment)|overdue (invoices?|payment|balance)|payment (is )?due|invoices? (attached|due|number|no\.?|#)|remittance advice|pro ?forma invoices?|final demand|swift copy)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "reward_lure",
      label: "Reward, prize or refund lure",
      category: "Social Engineering",
      weight: 12,
      severity: "medium",
      explain: "Promises of prizes, refunds or windfalls are bait. If you did not enter a competition, you have not won one.",
      advice: "Ignore or report it. Never pay a 'fee' or provide details to release a prize or refund.",
      run: function (ctx) {
        return matchList(/\b(you (have )?won|you'?ve won|congratulations|you (have been|are|were) (selected|chosen)|claim your (prizes?|rewards?|gifts?|refunds?|money)|lottery|sweepstake\w*|free (gift|iphone|prize|voucher)s?|unclaimed (fund|money|prize)s?|tax refunds?|refund of)\b/gi, ctx.content, 6);
      }
    },
    {
      id: "macro_enable",
      label: "Asks you to enable macros or content",
      category: "Malicious Attachments",
      weight: 20,
      severity: "high",
      group: "macro",
      explain: "Macros are a classic way to run malicious code inside a document. Legitimate senders have almost no reason to ask you to enable them.",
      advice: "Never enable macros or 'content' in a document from an unexpected email. Delete it or report it to IT.",
      run: function (ctx) {
        return matchList(/\b(enable (macros?|content|editing|active content)|macros? (must|need to|have to) be (enabled|allowed|turned on)|click (to )?(enable|allow) (content|macros|editing)|turn on macros|enable protected view)\b/gi, ctx.content, 6);
      }
    },

    /* ---------- Suspicious URLs ---------- */
    {
      id: "shortened_url",
      label: "Shortened URL (hidden destination)",
      category: "Suspicious Links",
      weight: 12,
      severity: "medium",
      explain: "Short links hide where they actually lead. Attackers use them so you cannot see the real (often malicious) address before clicking.",
      advice: "Do not click. If you must know where it goes, hover over it or use a link-expander you trust \u2014 or simply avoid it.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.urls.length; i++) {
          var h = ctx.urls[i].host;
          for (var j = 0; j < SHORTENERS.length; j++) {
            if (h === SHORTENERS[j] || h.slice(-(SHORTENERS[j].length + 1)) === "." + SHORTENERS[j]) {
              hits.push(ctx.urls[i].raw);
              break;
            }
          }
          if (hits.length >= 5) break;
        }
        return hits.length ? hits : null;
      }
    },
    {
      id: "raw_ip_url",
      label: "Link uses a raw IP address",
      category: "Suspicious Links",
      weight: 15,
      severity: "high",
      explain: "Real services use domain names. A link pointing to a bare IP address such as http://203.0.113.10 is a strong sign of a throwaway attack server.",
      advice: "Do not open the link. Treat it as malicious.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.urls.length; i++) {
          if (isRawIPv4(ctx.urls[i].host)) hits.push(ctx.urls[i].raw);
          if (hits.length >= 5) break;
        }
        return hits.length ? hits : null;
      }
    },
    {
      id: "suspicious_tld",
      label: "Domain uses a high-risk top-level domain",
      category: "Suspicious Links",
      weight: 8,
      severity: "low",
      explain: "Some inexpensive or free top-level domains (.zip, .top, .xyz, .tk and similar) are very heavily abused by phishing campaigns.",
      advice: "Be extra careful with links to these domains, especially if you do not recognise the organisation.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.urls.length; i++) {
          var h = "." + ctx.urls[i].host;
          for (var j = 0; j < SUSPICIOUS_TLDS.length; j++) {
            if (h.slice(-SUSPICIOUS_TLDS[j].length).toLowerCase() === SUSPICIOUS_TLDS[j]) {
              hits.push(ctx.urls[i].raw);
              break;
            }
          }
          if (hits.length >= 5) break;
        }
        return hits.length ? hits : null;
      }
    },
    {
      id: "punycode_or_userinfo",
      label: "Deceptive URL trick (look-alike or @ trick)",
      category: "Suspicious Links",
      weight: 10,
      severity: "medium",
      explain: "Attackers use look-alike characters ('xn--' punycode, imitating a real brand) or the '@' trick, where everything before the @ is a decoy and only the part after it is the real destination.",
      advice: "Do not trust the visible start of a link. Read the real domain carefully, or avoid the link entirely.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.urls.length; i++) {
          var u = ctx.urls[i];
          if (u.host.indexOf("xn--") !== -1) hits.push(u.raw + "   (look-alike characters)");
          else if (u.hasUserInfo) hits.push(u.raw + "   (@ hides the real domain)");
          if (hits.length >= 5) break;
        }
        return hits.length ? hits : null;
      }
    },
    {
      id: "misleading_link_text",
      label: "Misleading link text (shown text differs from destination)",
      category: "Suspicious Links",
      weight: 15,
      severity: "high",
      explain: "In HTML emails, the words you see can be different from the address the link actually goes to. This is a very common trick to make a malicious link look official.",
      advice: "Hover over a link (without clicking) to see the real address, or avoid it. On mobile, press and hold to preview the link.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.anchors.length; i++) {
          var a = ctx.anchors[i];
          var shown = a.text.replace(/\s+/g, " ").trim();
          var shownHostMatch = shown.match(/([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
          if (!shownHostMatch) continue;
          var shownHost = shownHostMatch[1].toLowerCase();
          var realHost = parseUrl(a.href).host;
          if (!realHost) continue;
          var shownReg = HP.registrableDomain(shownHost);
          var realReg = HP.registrableDomain(realHost);
          if (shownReg && realReg && shownReg !== realReg) {
            hits.push("shown: \"" + shown + "\"   actually goes to: " + realHost);
          }
          if (hits.length >= 4) break;
        }
        return hits.length ? hits : null;
      }
    },
    {
      id: "brand_in_subdomain",
      label: "Brand name hidden inside the link's sub-domain",
      category: "Suspicious Links",
      weight: 12,
      severity: "medium",
      explain: "A link like microsoft.com.secure-login.tk contains a brand name only to fool you. The real domain is the part right before the final '.tk' \u2014 not the brand.",
      advice: "Read a link from the first single '/' backwards. The true domain is the two labels just before the path.",
      run: function (ctx) {
        var hits = [];
        for (var i = 0; i < ctx.urls.length; i++) {
          var u = ctx.urls[i];
          var host = u.host.replace(/^www\./, "");
          var reg = HP.registrableDomain(host);
          for (var j = 0; j < BRANDS.length; j++) {
            var brand = BRANDS[j];
            if (host.indexOf(brand) !== -1 && reg.indexOf(brand) === -1) {
              hits.push(u.raw + "   (real domain: " + reg + ")");
              break;
            }
          }
          if (hits.length >= 4) break;
        }
        return hits.length ? hits : null;
      }
    },

    /* ---------- Malicious attachments ---------- */
    {
      id: "executable_attachment",
      label: "Executable attachment",
      category: "Malicious Attachments",
      weight: 25,
      severity: "high",
      group: "execfile",
      explain: "Files such as .exe, .scr, .bat, .js or .lnk can run code or install malware the moment they are opened. They are almost never sent as ordinary business attachments.",
      advice: "Do not open or download it. Report the email to your IT or security team.",
      run: function (ctx) {
        return matchList(EXEC_FILE_RE, ctx.filenameText, 5);
      }
    },
    {
      id: "double_extension",
      label: "Attachment with a doubled file extension",
      category: "Malicious Attachments",
      weight: 18,
      severity: "high",
      group: "execfile",
      explain: "A file named invoice.pdf.exe looks like a PDF but is really a program. The second (real) extension is what Windows runs.",
      advice: "Do not open it. Legitimate documents never need a double extension.",
      run: function (ctx) {
        var re = new RegExp("\\.(" + DOC_EXTS.join("|") + ")\\.(" + EXEC_EXTS.join("|") + ")\\b", "gi");
        return matchList(re, ctx.body, 4);
      }
    },
    {
      id: "archive_attachment",
      label: "Archive or disc-image attachment",
      category: "Malicious Attachments",
      weight: 10,
      severity: "medium",
      explain: "Zip, RAR, 7z or ISO attachments are often used to smuggle malware past email filters. Attackers may also password-protect them to defeat scanning.",
      advice: "Be very cautious. Only open an archive if you were definitely expecting it and know the sender.",
      run: function (ctx) {
        return extHits(ctx, ARCHIVE_EXTS);
      }
    },
    {
      id: "html_attachment",
      label: "HTML file attachment",
      category: "Malicious Attachments",
      weight: 10,
      severity: "medium",
      explain: "An attached .html file can open a fake login page straight from your own computer, or trigger a download, without any warning from the browser.",
      advice: "Do not open it in a browser. Treat HTML attachments from unexpected senders as suspicious.",
      run: function (ctx) {
        return extHits(ctx, ["html", "htm", "shtml"]);
      }
    },

    /* ---------- Email authentication (only when headers are provided) ---------- */
    {
      id: "sender_replyto_mismatch",
      label: "Sender and Reply-To addresses do not match",
      category: "Email Authentication",
      weight: 15,
      severity: "high",
      explain: "When the visible 'From' domain and the 'Reply-To' domain differ, replies may be silently redirected to a different (attacker-controlled) mailbox.",
      advice: "Do not reply to the email. Contact the person or organisation using details you already trust.",
      run: function (ctx) {
        if (!ctx.fromAddr.domain || !ctx.replyTo.domain) return null;
        var fromReg = HP.registrableDomain(ctx.fromAddr.domain);
        var replyReg = HP.registrableDomain(ctx.replyTo.domain);
        if (fromReg && replyReg && fromReg !== replyReg) {
          return ["From: " + ctx.fromAddr.domain, "Reply-To: " + ctx.replyTo.domain];
        }
        return null;
      }
    },
    {
      id: "display_name_spoof",
      label: "Display name does not match the real address",
      category: "Email Authentication",
      weight: 12,
      severity: "medium",
      explain: "The friendly name shown by your mail app (e.g. 'Microsoft Support') can be completely made up. Only the part inside the angle brackets is the real address.",
      advice: "Always check the actual address, not the display name. If they disagree, treat the email as suspicious.",
      run: function (ctx) {
        var from = ctx.fromAddr;
        if (!from.domain || !from.name) return null;
        var detail = null;
        if (from.name.indexOf("@") !== -1) {
          detail = "display name contains an address: \"" + from.name + "\"";
        } else {
          var m = from.name.match(/([a-z0-9-]+(?:\.[a-z0-9-]+)+)/i);
          if (m && HP.registrableDomain(m[1]) !== HP.registrableDomain(from.domain)) {
            detail = "display name shows \"" + m[1] + "\" but the real address is " + from.domain;
          }
        }
        if (!detail) {
          var lowerName = from.name.toLowerCase();
          for (var i = 0; i < BRANDS.length; i++) {
            if (lowerName.indexOf(BRANDS[i]) !== -1 && HP.registrableDomain(from.domain).indexOf(BRANDS[i]) === -1) {
              detail = "display name claims to be \"" + from.name + "\" but the real address is " + from.domain;
              break;
            }
          }
        }
        return detail ? [detail] : null;
      }
    },
    {
      id: "spf_fail",
      label: "SPF authentication failed",
      category: "Email Authentication",
      weight: 18,
      severity: "high",
      explain: "SPF checks whether the sending server was allowed to send mail for that domain. A 'fail' or 'softfail' means the email may have been sent by an unauthorised server.",
      advice: "Treat the email with strong suspicion. Do not rely on it for any account or payment action.",
      run: function (ctx) {
        if (!ctx.auth) return null;
        if (ctx.auth.spf === "fail" || ctx.auth.spf === "softfail" || ctx.auth.spf === "permerror") {
          return ["Authentication-Results: spf=" + ctx.auth.spf];
        }
        return null;
      }
    },
    {
      id: "dkim_fail",
      label: "DKIM authentication failed",
      category: "Email Authentication",
      weight: 15,
      severity: "high",
      explain: "DKIM is a digital signature that helps prove an email was not altered in transit. A failed DKIM check means the signature did not verify, so the message may have been tampered with or forged.",
      advice: "Treat the email with strong suspicion, especially if it asks you to act or pay.",
      run: function (ctx) {
        if (!ctx.auth) return null;
        if (ctx.auth.dkim === "fail" || ctx.auth.dkim === "permerror") {
          return ["Authentication-Results: dkim=" + ctx.auth.dkim];
        }
        return null;
      }
    },
    {
      id: "dmarc_fail",
      label: "DMARC authentication failed",
      category: "Email Authentication",
      weight: 18,
      severity: "high",
      explain: "DMARC ties SPF and DKIM together and tells receiving servers what to do when an email fails. A DMARC failure is a strong indicator that the email is not genuinely from the domain it claims.",
      advice: "Do not click, reply or act on the email. Report it to your IT or security team.",
      run: function (ctx) {
        if (!ctx.auth) return null;
        if (ctx.auth.dmarc === "fail") {
          return ["Authentication-Results: dmarc=fail"];
        }
        return null;
      }
    },
    {
      id: "auth_clean",
      label: "Authentication checks passed",
      category: "Email Authentication",
      weight: 0,
      severity: "info",
      explain: "The header authentication checks that were present passed. This is a good sign, but it is NOT proof the email is safe: an attacker can use a genuine domain, or a real account can be compromised.",
      advice: "Still verify unexpected requests independently before acting on them.",
      run: function (ctx) {
        if (!ctx.auth) return null;
        var vals = [ctx.auth.spf, ctx.auth.dkim, ctx.auth.dmarc].filter(function (v) { return v !== null; });
        if (!vals.length) return null;
        var allPass = vals.every(function (v) { return v === "pass"; });
        return allPass ? ["spf=" + ctx.auth.spf + "   dkim=" + ctx.auth.dkim + "   dmarc=" + ctx.auth.dmarc] : null;
      }
    },
    {
      id: "auth_missing",
      label: "No authentication headers found",
      category: "Email Authentication",
      weight: 0,
      severity: "info",
      explain: "Headers were provided, but no SPF, DKIM or DMARC results were present, so those checks could not be performed. This is common if the email was copied from a body-only view.",
      advice: "If possible, view the full raw headers in your mail app ('Show original' / 'View source') and paste them for a more thorough check.",
      run: function (ctx) {
        if (!ctx.hasHeaders || !ctx.auth) return null;
        var any = ctx.auth.spf || ctx.auth.dkim || ctx.auth.dmarc || ctx.auth.receivedSpf;
        return any ? null : ["no SPF / DKIM / DMARC results were present in the pasted headers"];
      }
    }
  ];

  /** Return evidence snippets for filenames whose extension is in `exts`. */
  function extHits(ctx, exts) {
    var out = [];
    for (var i = 0; i < ctx.filenames.length; i++) {
      var f = ctx.filenames[i];
      var ext = (f.split(".").pop() || "").toLowerCase();
      if (exts.indexOf(ext) !== -1) out.push(f);
      if (out.length >= 5) break;
    }
    return out.length ? out : null;
  }

  /* ---------------------------------------------------------------- */
  /*  Extracting things from the email text                            */
  /* ---------------------------------------------------------------- */

  // Pull http(s):// and www. addresses out of free text.
  var URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"'()\[\]{}]+/gi;

  // Pull <a href="...">visible text</a> pairs out of HTML email.
  var ANCHOR_RE = /<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

  // Filenames with a recognisable extension, e.g. "Invoice.pdf", "update.exe".
  // The legacy ".com" program type is left out so domain names cannot match.
  var FILENAME_RE = /\b[\w][\w \-\u2013]{0,60}\.(?:exe|scr|pif|bat|cmd|msi|vbs|vbe|js|jse|wsf|wsh|hta|ps1|psm1|jar|lnk|reg|cpl|gadget|inf|zip|rar|7z|iso|img|cab|gz|tar|ace|html?|shtml|docx?|xlsx?|pptx?|pdf|csv|txt)\b/gi;

  // Executable filenames only. The leading part is LAZY ({0,60}?) so that in a
  // name like "Invoice.pdf.exe" the engine skips past ".pdf" and matches the
  // real ".exe" ending — the extension that actually matters.
  var EXEC_FILE_RE = /\b[\w][\w \-\u2013]{0,60}?\.(?:exe|scr|pif|bat|cmd|msi|vbs|vbe|js|jse|wsf|wsh|hta|ps1|psm1|jar|lnk|reg|cpl|gadget|inf)\b/gi;

  /** Build the "context" object every rule receives. */
  function buildContext(rawInput) {
    var split = HP.splitHeadersAndBody(rawInput);
    var headers = split.hasHeaders ? HP.parseHeaders(split.headersText) : {};
    var subject = headers["subject"] ? headers["subject"][0] : "";
    var body = split.body || "";

    // Text rules look at the subject plus the body. Header lines are excluded so
    // that, for example, a "Reply-To:" value is not mistaken for body wording.
    //
    // Real emails are line-wrapped, which would otherwise break multi-word
    // phrases (e.g. "enable\nmacros"). So we collapse every run of whitespace
    // into a single space before matching phrases. This is why the analyser
    // still catches wording that is split across two lines.
    var content = ((subject ? subject + " " : "") + body).replace(/\s+/g, " ").trim();

    // --- URLs ---
    var urls = [];
    var rawUrls = matchList(URL_RE, content, 40);
    for (var i = 0; i < rawUrls.length; i++) {
      var cleaned = rawUrls[i].replace(/[.,;:!?]+$/, "");
      var parsed = parseUrl(cleaned);
      if (parsed.host) {
        parsed.raw = cleaned;
        urls.push(parsed);
      }
    }

    // --- HTML anchors (for misleading-link-text detection) ---
    var anchors = [];
    var am;
    ANCHOR_RE.lastIndex = 0;
    while ((am = ANCHOR_RE.exec(content)) !== null) {
      anchors.push({ href: am[1], text: am[2].replace(/<[^>]*>/g, " ") });
      if (anchors.length >= 40) break;
    }

    // --- Filenames mentioned in the text ---
    // URLs and email addresses are removed first, so a domain such as
    // "example.com" can never be mistaken for a file named "example.com".
    var filenameText = content
      .replace(/(?:https?:\/\/|www\.)[^\s<>"'()\[\]{}]+/gi, " ")
      .replace(/[\w.+-]+@[\w.-]+\.\w+/g, " ");
    var filenames = matchList(FILENAME_RE, filenameText, 12);

    // --- Addresses from the headers (may be blank) ---
    var fromAddr = HP.extractAddress(HP.first(headers, "from"));
    var replyTo = HP.extractAddress(HP.first(headers, "reply-to"));
    var returnPath = HP.extractAddress(HP.first(headers, "return-path"));

    var auth = split.hasHeaders ? HP.analyseAuthentication(headers) : null;

    return {
      raw: rawInput,
      hasHeaders: split.hasHeaders,
      headers: headers,
      subject: subject,
      body: body,
      content: content,
      urls: urls,
      anchors: anchors,
      filenames: filenames,
      filenameText: filenameText,
      fromAddr: fromAddr,
      replyTo: replyTo,
      returnPath: returnPath,
      auth: auth
    };
  }

  /* ---------------------------------------------------------------- */
  /*  The main entry point                                             */
  /* ---------------------------------------------------------------- */

  /**
   * Analyse a pasted email.
   * @param {string} rawInput
   * @returns {Object} result, or { error: "..." } for empty input
   */
  function analyse(rawInput) {
    var text = String(rawInput || "").trim();
    if (text.length < 15) {
      return { error: "Please paste the contents of an email (at least a line or two) and try again." };
    }

    var ctx = buildContext(rawInput);

    // Run every rule and keep the ones that fired.
    var fired = [];
    for (var i = 0; i < RULES.length; i++) {
      var rule = RULES[i];
      var evidence = null;
      try {
        evidence = rule.run(ctx);
      } catch (e) {
        evidence = null; // a failing rule must never break the whole analysis
      }
      if (evidence && evidence.length) {
        fired.push({
          id: rule.id,
          label: rule.label,
          category: rule.category,
          weight: rule.weight,
          severity: rule.severity,
          group: rule.group || null,
          explain: rule.explain,
          advice: rule.advice,
          evidence: evidence
        });
      }
    }

    // De-duplicate rules that share a group: keep only the highest weight.
    var bestByGroup = {};
    for (var g = 0; g < fired.length; g++) {
      var f = fired[g];
      if (!f.group) continue;
      if (!bestByGroup[f.group] || f.weight > bestByGroup[f.group].weight) {
        bestByGroup[f.group] = f;
      }
    }
    var hits = fired.filter(function (f) {
      if (!f.group) return true;
      return bestByGroup[f.group] === f;
    });

    // Sort: highest points first, then alphabetical by label for a stable order.
    hits.sort(function (a, b) {
      if (b.weight !== a.weight) return b.weight - a.weight;
      return a.label < b.label ? -1 : (a.label > b.label ? 1 : 0);
    });

    // The score is the sum of the fixed weights, capped at 100. Simple on purpose.
    var rawScore = 0;
    for (var h = 0; h < hits.length; h++) rawScore += hits[h].weight;
    var score = Math.min(100, rawScore);

    var level, levelLabel, summary;
    if (score >= 60) {
      level = "high";
      levelLabel = "High Risk";
      summary = "This email shows several strong warning signs of phishing or fraud. Treat it as dangerous until you can verify it independently.";
    } else if (score >= 25) {
      level = "sus";
      levelLabel = "Suspicious";
      summary = "This email shows some warning signs of phishing. Do not act on it until you have verified it through an independent, trusted route.";
    } else {
      level = "low";
      levelLabel = "Low Risk";
      summary = "Few or no warning signs were detected. That is reassuring, but it is not a guarantee \u2014 always verify unexpected requests independently.";
    }

    if (score === 0) {
      summary = "No warning signs from our checklist were detected. That is reassuring, but it is not a guarantee \u2014 always verify unexpected requests independently.";
    }

    var counts = { high: 0, medium: 0, low: 0, info: 0 };
    for (var c = 0; c < hits.length; c++) {
      if (counts[hits[c].severity] !== undefined) counts[hits[c].severity]++;
    }

    return {
      score: score,
      rawScore: rawScore,
      capped: rawScore > 100,
      level: level,
      levelLabel: levelLabel,
      summary: summary,
      hits: hits,
      counts: counts,
      totalRules: RULES.length,
      meta: {
        hasHeaders: ctx.hasHeaders,
        urlCount: ctx.urls.length,
        auth: ctx.auth,
        fromDomain: ctx.fromAddr.domain,
        replyToDomain: ctx.replyTo.domain
      }
    };
  }

  window.Analyzer = {
    analyse: analyse,
    RULES: RULES,
    parseUrl: parseUrl,
    isRawIPv4: isRawIPv4
  };
})();
