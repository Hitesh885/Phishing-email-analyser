/* =========================================================================
   headerParser.js
   ------------------------------------------------------------------------
   OPTIONAL extras used when the visitor pastes email *headers* as well as the
   body. Email headers are the routing/technical lines that begin with names
   like "From:", "Reply-To:", "Received-SPF:" or "Authentication-Results:".

   This file only *reads* text. It never sends anything anywhere. It gives the
   analyser a small, tidy object describing the sender addresses and any
   SPF / DKIM / DMARC results that were present.

   Exposed globally as: window.HeaderParser
   ========================================================================= */
(function () {
  "use strict";

  // A header line looks like:  "Reply-To: someone@example.com"
  var HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]*:\s?.*$/;

  /**
   * Decide whether the pasted text contains a header block, and if so split it
   * from the body.
   * @param {string} raw  the raw text the visitor pasted
   * @returns {{ hasHeaders: boolean, headersText: string, body: string }}
   */
  function splitHeadersAndBody(raw) {
    var text = String(raw || "");

    // The body normally starts after the first completely blank line.
    var blankIdx = text.search(/\r?\n[ \t]*\r?\n/);

    var headPart;
    var bodyPart;

    if (blankIdx !== -1) {
      headPart = text.slice(0, blankIdx);
      bodyPart = text.slice(blankIdx).replace(/^\s*\r?\n[ \t]*\r?\n/, "");
    } else {
      // No blank line at all. Treat the whole thing as headers only if it
      // genuinely looks like a header block; otherwise it is all body.
      headPart = text;
      bodyPart = "";
    }

    var lines = headPart.split(/\r?\n/).filter(function (l) { return l.trim() !== ""; });
    var headerLike = lines.filter(function (l) { return HEADER_LINE.test(l); }).length;

    // Require at least two header-looking lines to call it a real header block.
    var hasHeaders = headerLike >= 2 && headerLike >= lines.length - 1;

    if (!hasHeaders) {
      return { hasHeaders: false, headersText: "", body: text };
    }
    return { hasHeaders: true, headersText: headPart, body: bodyPart };
  }

  /**
   * Parse a header block into a lower-cased map of name -> array of values.
   * Handles "folded" headers (a value continued on the next indented line) and
   * repeated headers such as multiple "Received:" lines.
   * @param {string} headersText
   * @returns {Object.<string, string[]>}
   */
  function parseHeaders(headersText) {
    var map = {};
    if (!headersText) return map;

    var lines = String(headersText).split(/\r?\n/);
    var currentName = null;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];

      if (/^[ \t]/.test(line) && currentName) {
        // Continuation of the previous header value.
        var arr = map[currentName];
        arr[arr.length - 1] += " " + line.trim();
        continue;
      }

      var m = line.match(/^([A-Za-z][A-Za-z0-9-]*):\s?(.*)$/);
      if (!m) continue;

      currentName = m[1].toLowerCase();
      if (!map[currentName]) map[currentName] = [];
      map[currentName].push(m[2].trim());
    }
    return map;
  }

  /** Pull the first matching header value (case-insensitive). */
  function first(map, name) {
    var v = map[name.toLowerCase()];
    return v && v.length ? v[0] : "";
  }

  /**
   * Pull the display name, address and domain out of a "From:" style value.
   * Handles "Display Name <user@domain>", "user@domain" and '"Last, First" <..>'.
   */
  function extractAddress(value) {
    var raw = String(value || "").trim();
    var out = { raw: raw, name: "", email: "", domain: "" };
    if (!raw) return out;

    var email = "";
    var name = "";

    var angle = raw.match(/^(.*)<([^>]+)>\s*$/);
    if (angle) {
      name = angle[1].trim().replace(/^["']|["']$/g, "").trim();
      email = angle[2].trim();
    } else {
      email = raw.replace(/[<>]/g, "").trim();
    }

    var at = email.lastIndexOf("@");
    if (at !== -1) out.domain = email.slice(at + 1).trim().toLowerCase();

    out.name = name;
    out.email = email.toLowerCase();
    return out;
  }

  /**
   * Rough "registrable domain": the last two labels of the host.
   * e.g. a.b.example.co.uk -> "co.uk" (kept deliberately simple and documented).
   */
  function registrableDomain(host) {
    if (!host) return "";
    var h = String(host).toLowerCase().replace(/\.$/, "");
    var parts = h.split(".");
    if (parts.length <= 2) return h;
    return parts.slice(-2).join(".");
  }

  /**
   * Read SPF / DKIM / DMARC results out of the headers we understand.
   * Returns e.g. { spf: "fail", dkim: "pass", dmarc: "none", receivedSpf: ... }
   * Values are lower-case strings, or null when not present.
   */
  function analyseAuthentication(map) {
    var result = { spf: null, dkim: null, dmarc: null, receivedSpf: null };

    // 1) Received-SPF: pass (or fail/softfail/neutral/none/temperror/permerror)
    var received = first(map, "received-spf");
    if (received) {
      var r = received.match(/^\s*(pass|fail|softfail|neutral|none|temperror|permerror)/i);
      if (r) {
        result.receivedSpf = r[1].toLowerCase();
        if (result.spf === null) result.spf = result.receivedSpf;
      }
    }

    // 2) Authentication-Results: "... spf=fail ... dkim=pass ... dmarc=fail ..."
    var authLines = map["authentication-results"] || [];
    for (var i = 0; i < authLines.length; i++) {
      var line = authLines[i];
      var pat = /(spf|dkim|dmarc)=([a-z]+)/gi;
      var m;
      while ((m = pat.exec(line)) !== null) {
        var key = m[1].toLowerCase();
        var val = m[2].toLowerCase();
        if (key === "spf" && result.spf === null) result.spf = val;
        if (key === "dkim" && result.dkim === null) result.dkim = val;
        if (key === "dmarc" && result.dmarc === null) result.dmarc = val;
      }
    }

    // 3) A DKIM-Signature header existing is a hint DKIM was attempted.
    result.hasDkimSignature = !!(map["dkim-signature"] && map["dkim-signature"].length);

    return result;
  }

  window.HeaderParser = {
    splitHeadersAndBody: splitHeadersAndBody,
    parseHeaders: parseHeaders,
    extractAddress: extractAddress,
    registrableDomain: registrableDomain,
    analyseAuthentication: analyseAuthentication,
    first: first
  };
})();
