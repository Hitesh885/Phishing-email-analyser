/* =========================================================================
   tests/sample-preview.js  —  extra practice emails + a scoring preview
   ------------------------------------------------------------------------
   Developer/learning aid (NOT part of the website).

   It scores a set of additional FICTIONAL emails so you can see exactly what
   the analyser reports before you paste them in yourself. Everything here is
   made up: no real company is impersonated, and all links use reserved or
   fabricated domains (example.com/.org, .invalid, .test, .tk, .xyz) and
   documentation IP addresses (RFC 5737: 203.0.113.x, 198.51.100.x) which are
   never routed on the real internet. Nothing here is clickable or harmful.

   Run with:  cscript //nologo tests\sample-preview.js
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

var window = {};

// Compatibility shims for the old Windows script engine.
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
  Array.prototype.forEach = function (fn, t) {
    for (var i = 0; i < this.length; i++) fn.call(t, this[i], i, this);
  };
}
if (!Array.prototype.map) {
  Array.prototype.map = function (fn, t) {
    var o = [];
    for (var i = 0; i < this.length; i++) o.push(fn.call(t, this[i], i, this));
    return o;
  };
}
if (!Array.prototype.filter) {
  Array.prototype.filter = function (fn, t) {
    var o = [];
    for (var i = 0; i < this.length; i++) if (fn.call(t, this[i], i, this)) o.push(this[i]);
    return o;
  };
}
if (!Array.prototype.every) {
  Array.prototype.every = function (fn, t) {
    for (var i = 0; i < this.length; i++) if (!fn.call(t, this[i], i, this)) return false;
    return true;
  };
}
if (!Date.now) { Date.now = function () { return new Date().getTime(); }; }

eval(loadFile("js\\headerParser.js"));
eval(loadFile("js\\analyzer.js"));

var Analyzer = window.Analyzer;

var EMAILS = [

  {
    name: "1. Bank 'account suspended' / KYC scam",
    text: [
      'From: "SecureBank Alerts" <alerts@securebank-verify.invalid>',
      'Reply-To: "SecureBank" <no-reply@securebank-support.invalid>',
      "Subject: Action required: your online banking access is suspended",
      "",
      "Dear Customer,",
      "",
      "We have suspended your online banking access after detecting unusual",
      "activity on your account. Your account will be permanently closed within",
      "48 hours unless you re-activate it.",
      "",
      "To restore access you must verify your identity and confirm your password",
      "at the link below:",
      "",
      "http://securebank-login.example.com.verify-account.tk/restore",
      "",
      "You will also be asked to confirm your card number and PIN.",
      "",
      "Failure to verify your account will result in permanent account closure.",
      "",
      "SecureBank Security Team"
    ].join("\n")
  },

  {
    name: "2. Crypto 'double your money' scam",
    text: [
      'From: "Marcus Reed" <marcus.reed@crypto-prosper.invalid>',
      "Subject: Exclusive: turn 250 into 5,000 in 7 days",
      "",
      "Hello,",
      "",
      "I am a certified blockchain investment consultant with 12 years of",
      "experience. Our verified trading bot has helped over 9,000 investors",
      "double their bitcoin.",
      "",
      "Send a minimum of 0.05 BTC to our secure wallet and receive your returns",
      "within 7 days. Limited places - act now.",
      "",
      "Reply with your wallet address to begin.",
      "",
      "Investment Team"
    ].join("\n")
  },

  {
    name: "3. Fake job offer / recruitment scam",
    text: [
      'From: "Talent Acquisition" <careers@global-staffing.invalid>',
      "Subject: Immediate job offer - work from home, 450 per day",
      "",
      "Dear Candidate,",
      "",
      "We reviewed your CV online and would like to offer you a remote position.",
      "No interview is required. You must be available immediately.",
      "",
      "To begin, please confirm your full name, address and bank account number",
      "so we can set up your direct deposit. You will also need to purchase",
      "your own equipment - reply for details.",
      "",
      "HR Department"
    ].join("\n")
  },

  {
    name: "4. IT helpdesk password expiry (with failing auth headers)",
    text: [
      'From: "IT Service Desk" <it.servicedesk@university-accounts.invalid>',
      'Reply-To: "IT Service Desk" <helpdesk.reset@mail-relay.invalid>',
      "Subject: Your account password expires in 2 hours",
      "Authentication-Results: mx.example.invalid; spf=fail smtp.mailfrom=university-accounts.invalid; dkim=fail header.d=university-accounts.invalid; dmarc=fail",
      "Received-SPF: fail (example.invalid: domain does not designate 203.0.113.77 as a permitted sender)",
      "",
      "Dear User,",
      "",
      "Your network password expires in 2 hours. If you do not act, you will lose",
      "access to your email and your files.",
      "",
      "Click below to re-enter your credentials and keep your current password:",
      "",
      "https://university-sso.invalid/session/keep-alive",
      "",
      "Enter the 6-digit code we sent to your phone if prompted.",
      "",
      "IT Service Desk"
    ].join("\n")
  },

  {
    name: "5. Fake tax refund lure",
    text: [
      'From: "Tax Office" <refunds@tax-refund-centre.invalid>',
      "Subject: You are eligible for a tax refund of 428.90",
      "",
      "Dear Taxpayer,",
      "",
      "Our records show you are entitled to a refund of 428.90. To claim your",
      "money you must confirm your details and provide your card number for the",
      "refund transfer.",
      "",
      "Claim your refund within 24 hours or it will be returned to the treasury.",
      "",
      "Tax Refund Centre"
    ].join("\n")
  },

  {
    name: "6. Fake Microsoft 'unusual sign-in' (HTML link)",
    text: [
      'From: "Microsoft account team" <no-reply@account-protection.example.org>',
      "Subject: Unusual sign-in activity",
      "",
      "We detected something unusual about a recent sign-in to your Microsoft",
      "account. Someone may have accessed your account.",
      "",
      '<a href="http://microsoft-account.example.org.session-check.xyz/verify">https://account.microsoft.com/security</a>',
      "",
      "If this was not you, please review your recent activity immediately and",
      "verify your account.",
      "",
      "The Microsoft account team"
    ].join("\n")
  },

  {
    name: "7. CEO gift-card request",
    text: [
      'From: "Rebecca Hall" <rebecca.hall@examplecorp.invalid>',
      'Reply-To: "R. Hall" <rhall.private@mailbox-free.invalid>',
      "Subject: Quick favour",
      "",
      "Hi,",
      "",
      "Are you at your desk? I am in back-to-back meetings and cannot talk.",
      "",
      "I need you to buy four 100 gift cards for a client thank-you. Send me the",
      "codes as soon as you have them, and keep this confidential - do not",
      "mention it to anyone yet.",
      "",
      "I will reimburse you today.",
      "",
      "Thanks,",
      "Rebecca",
      "CEO"
    ].join("\n")
  },

  {
    name: "8. 'Resume' malware with executable attachment",
    text: [
      'From: "HR Recruiting" <jobs@career-opportunities.invalid>',
      "Subject: Your application - please review the attached document",
      "",
      "Hi,",
      "",
      "Thank you for applying. Please review the attached document and enable",
      "macros to view the full job description.",
      "",
      "Attachment: Application_Review.pdf.exe",
      "",
      "If you have any issues, contact us at http://198.51.100.23/support",
      "",
      "Recruiting Team"
    ].join("\n")
  },

  {
    name: "9. Rowdy but legitimate shop promotion",
    text: [
      'From: "Deals Newsletter" <offers@shop-deals.example.com>',
      "Subject: Last chance - your 20% discount code expires tonight",
      "",
      "Dear Customer,",
      "",
      "Your 20% welcome discount expires tonight at midnight. Use code WELCOME20",
      "at checkout.",
      "",
      "Shop now: https://shop-deals.example.com/checkout?code=WELCOME20",
      "",
      "Unsubscribe from these emails.",
      "",
      "Deals Team"
    ].join("\n")
  },

  {
    name: "10. Genuine bank notification (with passing auth headers)",
    text: [
      'From: "SecureBank" <statements@securebank.example.com>',
      'To: "James Carter" <james.carter@example.com>',
      "Subject: Your January statement is ready",
      "Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=securebank.example.com; dkim=pass header.d=securebank.example.com; dmarc=pass",
      "",
      "Dear James,",
      "",
      "Your January statement is now available to view in the SecureBank app.",
      "",
      "We never include sign-in links in our emails. Please open the app, or type",
      "securebank.example.com into your browser, to review your account.",
      "",
      "If you have any questions, please call the number printed on your card.",
      "",
      "Kind regards,",
      "SecureBank"
    ].join("\n")
  }
];

// --- Score them all and print a readable report -----------------------
WScript.Echo("");
WScript.Echo("Sample preview - extra practice emails");
WScript.Echo("======================================");

for (var i = 0; i < EMAILS.length; i++) {
  var r = Analyzer.analyse(EMAILS[i].text);
  WScript.Echo("");
  WScript.Echo(EMAILS[i].name);
  WScript.Echo("   score : " + r.score + "/100  ->  " + r.levelLabel);
  var fired = [];
  for (var h = 0; h < r.hits.length; h++) {
    fired.push(r.hits[h].label + " (+" + r.hits[h].weight + ")");
  }
  WScript.Echo("   found : " + (fired.length ? fired.join("; ") : "nothing"));
}
WScript.Echo("");


