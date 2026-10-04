/* =========================================================================
   samples.js  —  Fictional demonstration emails
   ------------------------------------------------------------------------
   All six examples below are COMPLETELY MADE UP for teaching purposes.

   • No real company is impersonated and none of the addresses are real.
   • All links use reserved/fabricated domains (example.com, .invalid, .test)
     or documentation IP addresses (RFC 5737: 203.0.113.x) which are never
     routed on the public internet. None of them lead anywhere harmful.
   • The shortener example uses bit.ly purely to demonstrate the detector;
     the code after it does not resolve to anything meaningful.

   Never copy these into a real mail client or click any link.

   Exposed globally as: window.Samples
   ========================================================================= */
(function () {
  "use strict";

  var SAMPLES = [

    /* ------------------------------------------------------------------ */
    {
      id: "obvious-phishing",
      name: "Obvious phishing",
      tag: "High risk",
      description: "A crude, classic phishing email: panic, a threat, a password request and a hidden link.",
      text: [
        'From: "Account Security Team" <security@account-verify-alerts.com>',
        'Reply-To: "Recovery Desk" <recovery@mailbox-restore.net>',
        "Subject: URGENT: Your account will be permanently suspended!",
        "",
        "Dear Customer,",
        "",
        "We have detected unusual activity on your account. Your account will be",
        "suspended within 24 hours unless you verify your information immediately.",
        "",
        "Click here to verify your account and restore access:",
        "http://bit.ly/verify-your-account-today",
        "",
        "You must confirm your password and update your billing details to avoid",
        "permanent account closure.",
        "",
        "Failure to act will result in the loss of your account and any funds.",
        "",
        "The Account Security Team"
      ].join("\n")
    },

    /* ------------------------------------------------------------------ */
    {
      id: "sophisticated-phishing",
      name: "Sophisticated phishing",
      tag: "Subtle",
      description: "Polite, believable and low-pressure. The giveaways are a look-alike link and quietly changed payment details.",
      text: [
        'From: "Sarah Whitfield (Finance)" <sarah.whitfield@globex-corporation.example.com>',
        'Reply-To: "Accounts" <accounts@globex-billing.example.net>',
        "Subject: Re: Q3 supplier remittance - revised details",
        "",
        "Hi James,",
        "",
        "Following our call earlier, I have revised the remittance details for the",
        "Q3 supplier payment. Could you update the bank account number on the next",
        "payment run so it goes out before month end?",
        "",
        "New bank account number: 40218 5570",
        "Sort code: 20-45-77",
        "",
        "You can review the figures in the portal here:",
        '<a href="http://globex-payments.example.com.verify-login.zip/signin">https://portal.globex-corporation.com/remittance</a>',
        "",
        "Many thanks,",
        "Sarah",
        "",
        "--",
        "Sarah Whitfield | Finance | Globex Corporation"
      ].join("\n")
    },

    /* ------------------------------------------------------------------ */
    {
      id: "fake-microsoft",
      name: "Fake Microsoft 365 warning",
      tag: "Headers included",
      description: "Impersonates a Microsoft 365 expiry notice. Includes fake headers so the SPF / DKIM / DMARC checks can fire.",
      text: [
        'From: "Microsoft 365" <no-reply@office365-security-alerts.invalid>',
        "To: james.carter@example.com",
        "Subject: Your Microsoft 365 password expires today",
        "Authentication-Results: mx.example.invalid; spf=fail smtp.mailfrom=office365-security-alerts.invalid; dkim=fail header.d=office365-security-alerts.invalid; dmarc=fail",
        "Received-SPF: fail (example.invalid: domain does not designate 203.0.113.45 as a permitted sender)",
        "",
        "Dear User,",
        "",
        "Your Microsoft 365 password expires today. To continue using your account",
        "you must sign in to verify your identity.",
        "",
        "Enter the verification code we sent to your phone to confirm the change.",
        "",
        "Sign in here to keep your password active:",
        "https://office365-verify.example.com.auth-check.zip/login",
        "",
        "If you do not verify your account within 24 hours, your mailbox will be",
        "deactivated.",
        "",
        "The Microsoft Account Team"
      ].join("\n")
    },

    /* ------------------------------------------------------------------ */
    {
      id: "parcel-delivery",
      name: "Fake parcel delivery",
      tag: "Common scam",
      description: "A 'missed delivery' message with a hidden short link and a deadline. A very common everyday phishing text.",
      text: [
        'From: "Delivery Updates" <notify@parcel-tracking.example.com>',
        "Subject: We could not deliver your parcel - action needed",
        "",
        "Dear Customer,",
        "",
        "Our courier attempted to deliver your parcel today but no one was available.",
        "Your parcel is now being held at our local depot.",
        "",
        "To arrange redelivery, please confirm your details here:",
        "http://bit.ly/parcel-redelivery-2048",
        "",
        "You must update your delivery details within 24 hours or the parcel will",
        "be returned to sender.",
        "",
        "Delivery Support"
      ].join("\n")
    },

    /* ------------------------------------------------------------------ */
    {
      id: "fake-invoice-bec",
      name: "Fake invoice / CEO fraud (BEC)",
      tag: "Business email compromise",
      description: "Pretends to be the CEO asking for a confidential urgent payment to a new bank account, with an executable-looking attachment.",
      text: [
        'From: "David Sterling (CEO)" <david.sterling@company-portal.invalid>',
        'Reply-To: "Finance" <finance.dept@secure-mail-relay.invalid>',
        "Subject: Urgent - confidential payment instruction",
        "",
        "Hi,",
        "",
        "I need you to process an urgent payment today to a new supplier before the",
        "deal is announced. Please keep this confidential until then - do not",
        "discuss it with anyone.",
        "",
        "Please find attached the invoice INV-2291.",
        "Attachment: Invoice_INV-2291.pdf.exe",
        "",
        "New bank account number: 8891 2233",
        "Sort code: 40-11-22",
        "Amount: GBP 18,450",
        "",
        "Let me know once the transfer is done.",
        "",
        "Best,",
        "David",
        "CEO"
      ].join("\n")
    },

    /* ------------------------------------------------------------------ */
    {
      id: "legitimate",
      name: "Legitimate email",
      tag: "Safe example",
      description: "An ordinary, expected message from a colleague. Should score very low \u2014 a good comparison.",
      text: [
        'From: "Priya Nair" <priya.nair@example.com>',
        'To: "James Carter" <james.carter@example.com>',
        "Subject: Notes from this morning's project meeting",
        "",
        "Hi James,",
        "",
        "Thanks for your time this morning. As discussed, I have put the meeting",
        "notes in our shared drive folder, which you can find here:",
        "https://intranet.example.com/projects/atlas/notes",
        "",
        "Just a reminder that the next sprint review is on Tuesday at 10am.",
        "",
        "Best regards,",
        "Priya"
      ].join("\n")
    }
  ];

  window.Samples = SAMPLES;
})();
