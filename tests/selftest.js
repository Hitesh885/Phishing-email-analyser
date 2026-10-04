/* =========================================================================
   tests/selftest.js  —  a tiny, dependency-free test runner
   ------------------------------------------------------------------------
   This file is NOT part of the website. It is a developer aid.

   It loads the real analyser files (headerParser.js, analyzer.js, samples.js),
   runs every fictional demo email through the engine, and checks that the
   results are sensible. It runs with Windows' built-in script host, so it
   needs no installation of Node.js or anything else.

   Run it from the project folder with:
       cscript //nologo tests\selftest.js
   ========================================================================= */

var fso = new ActiveXObject("Scripting.FileSystemObject");
var testsDir = fso.GetParentFolderName(WScript.ScriptFullName);
var root = fso.GetParentFolderName(testsDir);

function loadFile(relPath) {
  var f = fso.OpenTextFile(root + "\\" + relPath, 1);
  var s = f.ReadAll();
  f.Close();
  return s;
}

// A minimal stand-in for the browser's global "window" object.
var window = {};

// --- Compatibility shims for the old Windows script engine (JScript 5.8) ---
// Every browser has had these methods for over a decade; the ancient script
// host used to run this test does not, so we add simple equivalents here.
if (!String.prototype.trim) {
  String.prototype.trim = function () { return this.replace(/^\s+|\s+$/g, ""); };
}
if (!Array.prototype.indexOf) {
  Array.prototype.indexOf = function (item) {
    for (var i = 0; i < this.length; i++) if (this[i] === item) return i;
    return -1;
  };
}
if (!Array.prototype.forEach) {
  Array.prototype.forEach = function (fn, thisArg) {
    for (var i = 0; i < this.length; i++) fn.call(thisArg, this[i], i, this);
  };
}
if (!Array.prototype.map) {
  Array.prototype.map = function (fn, thisArg) {
    var out = [];
    for (var i = 0; i < this.length; i++) out.push(fn.call(thisArg, this[i], i, this));
    return out;
  };
}
if (!Array.prototype.filter) {
  Array.prototype.filter = function (fn, thisArg) {
    var out = [];
    for (var i = 0; i < this.length; i++) if (fn.call(thisArg, this[i], i, this)) out.push(this[i]);
    return out;
  };
}
if (!Array.prototype.every) {
  Array.prototype.every = function (fn, thisArg) {
    for (var i = 0; i < this.length; i++) if (!fn.call(thisArg, this[i], i, this)) return false;
    return true;
  };
}
if (!Date.now) {
  Date.now = function () { return new Date().getTime(); };
}

eval(loadFile("js\\headerParser.js"));
eval(loadFile("js\\analyzer.js"));
eval(loadFile("js\\samples.js"));

var Analyzer = window.Analyzer;
var Samples = window.Samples;

var passed = 0;
var failed = 0;

function check(label, condition, detail) {
  if (condition) {
    passed++;
    WScript.Echo("  PASS  " + label);
  } else {
    failed++;
    WScript.Echo("  FAIL  " + label + (detail ? "  ->  " + detail : ""));
  }
}

function analyseById(id) {
  for (var i = 0; i < Samples.length; i++) {
    if (Samples[i].id === id) return Analyzer.analyse(Samples[i].text);
  }
  throw new Error("sample not found: " + id);
}

function ids(result) {
  var out = [];
  for (var i = 0; i < result.hits.length; i++) out.push(result.hits[i].id);
  return out.join(", ");
}

function has(result, id) {
  for (var i = 0; i < result.hits.length; i++) if (result.hits[i].id === id) return true;
  return false;
}

WScript.Echo("");
WScript.Echo("Phishing Email Analyser - self test");
WScript.Echo("===================================");

// ---- Sample inventory -------------------------------------------------
check("six demo emails are present", Samples.length === 6, "found " + Samples.length);

var expectedSamples = ["obvious-phishing", "sophisticated-phishing", "fake-microsoft", "parcel-delivery", "fake-invoice-bec", "legitimate"];
for (var e = 0; e < expectedSamples.length; e++) {
  var found = false;
  for (var s = 0; s < Samples.length; s++) if (Samples[s].id === expectedSamples[e]) found = true;
  check("sample exists: " + expectedSamples[e], found);
}

// ---- Results for every sample -----------------------------------------
WScript.Echo("");
WScript.Echo("Results per demo email:");
WScript.Echo("------------------------");
var results = {};
for (var i = 0; i < Samples.length; i++) {
  var r = Analyzer.analyse(Samples[i].text);
  results[Samples[i].id] = r;
  WScript.Echo("");
  WScript.Echo("  " + Samples[i].name);
  WScript.Echo("    score : " + r.score + "/100  (" + r.levelLabel + ")");
  WScript.Echo("    rules : " + ids(r));
}

// ---- Expectations -----------------------------------------------------
WScript.Echo("");
WScript.Echo("Expectations:");
WScript.Echo("------------------------");

var obvious = results["obvious-phishing"];
check("obvious phishing is High Risk", obvious.level === "high", obvious.level);
check("obvious phishing is capped at 100", obvious.score === 100, String(obvious.score));
check("obvious phishing flags a password request", has(obvious, "password_request"));
check("obvious phishing flags a shortened URL", has(obvious, "shortened_url"));
check("obvious phishing flags account suspension", has(obvious, "account_suspension"));
check("obvious phishing flags sender/reply-to mismatch", has(obvious, "sender_replyto_mismatch"));

var soph = results["sophisticated-phishing"];
check("sophisticated phishing is not Low Risk", soph.level !== "low", soph.level);
check("sophisticated phishing flags bank detail change", has(soph, "bank_details_change"));
check("sophisticated phishing flags a misleading link", has(soph, "misleading_link_text"));

var ms = results["fake-microsoft"];
check("fake Microsoft 365 is High Risk", ms.level === "high", ms.level);
check("fake Microsoft 365 flags SPF failure", has(ms, "spf_fail"));
check("fake Microsoft 365 flags DKIM failure", has(ms, "dkim_fail"));
check("fake Microsoft 365 flags DMARC failure", has(ms, "dmarc_fail"));
check("fake Microsoft 365 flags an MFA code request", has(ms, "mfa_code_request"));
check("fake Microsoft 365 flags a password request", has(ms, "password_request"));

var parcel = results["parcel-delivery"];
check("parcel delivery is Suspicious or High", parcel.level === "sus" || parcel.level === "high", parcel.level);
check("parcel delivery flags a shortened URL", has(parcel, "shortened_url"));
check("parcel delivery flags a generic greeting", has(parcel, "generic_greeting"));

var bec = results["fake-invoice-bec"];
check("BEC invoice is High Risk", bec.level === "high", bec.level);
check("BEC invoice flags executable/malicious attachment", has(bec, "executable_attachment") || has(bec, "double_extension"));
check("BEC invoice flags a bank detail change", has(bec, "bank_details_change"));
check("BEC invoice flags secrecy", has(bec, "secrecy_request"));
check("BEC invoice flags sender/reply-to mismatch", has(bec, "sender_replyto_mismatch"));

var legit = results["legitimate"];
check("legitimate email scores Low Risk", legit.level === "low", legit.level);
check("legitimate email has no scoring warning signs",
  legit.hits.filter(function (h) { return h.weight > 0; }).length === 0,
  "scored " + legit.score);

// ---- Header parser unit checks ----------------------------------------
WScript.Echo("");
WScript.Echo("Header parser checks:");
WScript.Echo("------------------------");

var split = window.HeaderParser.splitHeadersAndBody("From: a@b.com\nSubject: hi\n\nHello there");
check("splits headers from body", split.hasHeaders === true && split.body.indexOf("Hello") === 0, split.body);

var split2 = window.HeaderParser.splitHeadersAndBody("Just an ordinary sentence with no headers at all.");
check("plain text is treated as body only", split2.hasHeaders === false, "hasHeaders=" + split2.hasHeaders);

var addr = window.HeaderParser.extractAddress('"Microsoft Support" <no-reply@fake-login.invalid>');
check("extracts display name", addr.name === "Microsoft Support", addr.name);
check("extracts domain", addr.domain === "fake-login.invalid", addr.domain);

var auth = window.HeaderParser.analyseAuthentication(
  window.HeaderParser.parseHeaders("Authentication-Results: mx; spf=pass dkim=fail dmarc=fail")
);
check("reads spf=pass", auth.spf === "pass", String(auth.spf));
check("reads dkim=fail", auth.dkim === "fail", String(auth.dkim));
check("reads dmarc=fail", auth.dmarc === "fail", String(auth.dmarc));

// ---- Edge cases -------------------------------------------------------
WScript.Echo("");
WScript.Echo("Edge cases:");
WScript.Echo("------------------------");

check("empty input returns an error", !!Analyzer.analyse("").error);
check("short input returns an error", !!Analyzer.analyse("hi").error);

var clean = Analyzer.analyse("Hi Sam,\n\nLunch at the usual place tomorrow at noon?\n\nThanks,\nAlex");
check("a short harmless note scores 0", clean.score === 0 && clean.level === "low", String(clean.score));

var urlOnly = Analyzer.analyse("Please log in at http://203.0.113.10/login to confirm your account");
check("raw IP address link is flagged", has(urlOnly, "raw_ip_url"));

// ---- Summary ----------------------------------------------------------
WScript.Echo("");
WScript.Echo("===================================");
WScript.Echo("PASSED: " + passed + "   FAILED: " + failed);
WScript.Echo("");
WScript.Quit(failed > 0 ? 1 : 0);
