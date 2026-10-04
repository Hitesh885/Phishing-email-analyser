# Phishing Email Analyser

A polished, **fully private** web application that highlights the warning signs of
phishing and social-engineering in an email you paste in. It gives you a risk score
from 0–100, a plain-English classification, an explanation of every warning sign it
found, and clear recommendations for what to do next.

Built for learning and personal triage. **It is not a verdict.**

---

## The most important thing: privacy

- **All analysis happens inside your web browser.** The email you paste is never sent
  anywhere — not to a server, not to an AI provider, not to an analytics service.
- **No tracking, no telemetry, no accounts, no cookies.**
- **No external network requests at all.** Fonts, icons and styling are all built in,
  so the page works completely **offline**.

You can even disconnect from the internet, open the page, and it still works.

---

## Quick start (you do not need to be a programmer)

1. Open the folder `Phishing E-Mail Analyser`.
2. **Double-click `index.html`.** It opens in your default web browser.
3. Paste an email into the box (or click one of the sample buttons).
4. Click **Analyse Email**.

That's it. There is nothing to install and nothing to compile.

> Tip: to get the SPF / DKIM / DMARC and sender checks, paste the email
> **with its headers**. In most mail apps that is **"Show original"** or
> **"View source"**. The analyser detects headers automatically.

---

## What it checks

| Area | Examples of what it looks for |
|------|-------------------------------|
| Urgency & pressure | "urgent", "within 24 hours", "final notice", "act now" |
| Account threats | "your account will be suspended / closed / restricted" |
| Credential theft | requests for **passwords**, **MFA / one-time codes**, "verify your account" |
| Payment fraud | gift cards, crypto, wire transfers, changing bank details |
| Impersonation | "IT helpdesk", "the Microsoft Account Team", "Dear Customer" |
| Social engineering | secrecy requests, surprise invoices, prize/refund lures |
| Suspicious links | shorteners, raw IP addresses, high-risk TLDs, the `@` trick, look-alike (punycode) domains |
| Misleading link text | the visible words differ from the real destination |
| Attachments | executable files, doubled extensions (`.pdf.exe`), archives, HTML files |
| Macros | "enable macros / enable content" |
| Email authentication* | sender vs Reply-To mismatch, SPF / DKIM / DMARC failures |

*Only when you paste the email headers.

---

## How the score works (no mystery numbers)

Every warning sign is a **rule** with a **fixed** number of points. The score is simply
the sum of the points for the rules that fired, **capped at 100**.

| Band | Meaning |
|------|---------|
| 0–24 | **Low Risk** |
| 25–59 | **Suspicious** |
| 60–100 | **High Risk** |

Some example rule weights:

| Warning sign | Points |
|--------------|--------|
| Executable attachment | +25 |
| Requests a password | +22 |
| Requests an MFA / verification code | +22 |
| Asks you to enable macros | +20 |
| Threat of account suspension | +15 |
| Raw IP address in a link | +15 |
| Misleading link text | +15 |
| Sender / Reply-To mismatch | +15 |
| Shortened URL | +12 |
| Urgency language | +10 |
| High-risk domain (.zip, .top, .tk…) | +8 |

The interface lists every rule that fired, the points it added, the evidence found in
the email, why it matters, and what to do — so the number is always explainable.

---

## Project structure

```
Phishing E-Mail Analyser/
├─ index.html            The page: layout, privacy notice, panels
├─ css/
│  └─ styles.css         All styling (dark cybersecurity theme, responsive)
├─ js/
│  ├─ headerParser.js    Reads email headers (From, Reply-To, SPF/DKIM/DMARC)
│  ├─ analyzer.js        THE BRAIN: every rule + the scoring engine
│  ├─ samples.js         Six fictional demo emails
│  └─ app.js             Connects the buttons to the engine and draws results
├─ tests/
│  └─ selftest.js        Dependency-free test runner (developer aid)
└─ README.md             This file
```

No frameworks, no build step, no dependencies, no backend. Plain HTML, CSS and
JavaScript only.

---

## The demo emails

Click any sample button to load a fictional example. **All six are completely made
up.** They impersonate nobody real, and their links use reserved or fabricated
domains (`example.com`, `.invalid`, `.test`) and documentation IP addresses
(RFC 5737, `203.0.113.x`) which never resolve on the public internet. Never copy them
into a real mail client.

| Sample | Expected result |
|--------|-----------------|
| Obvious phishing | ~100 / High Risk |
| Sophisticated phishing | ~56 / Suspicious |
| Fake Microsoft 365 warning | ~100 / High Risk |
| Fake parcel delivery | ~45 / Suspicious |
| Fake invoice / CEO fraud (BEC) | ~79 / High Risk |
| Legitimate email | 0 / Low Risk |

---

## Hosting it for free (optional)

Because this is a **static site**, you can publish it at no cost and with no server.
You literally upload these files and visitors use it. Good free options:

- **GitHub Pages** — create a repository, upload the files, enable Pages in Settings.
- **Netlify Drop** — drag the whole folder onto app.netlify.com/drop.
- **Cloudflare Pages** — connect a repository or upload directly.

There is no backend to configure, no environment variables, and no keys. The site
remains free to host and free for visitors.

---

## Running the tests (optional, for the curious)

There is a small self-test that runs the six demo emails through the engine and
checks the results. It uses Windows' built-in script host, so **nothing needs to be
installed**.

Open a Command Prompt or PowerShell **in the project folder** and run:

```
cscript //nologo tests\selftest.js
```

You should see `PASSED: 43   FAILED: 0`. If you ever change a rule, run this again to
make sure the demo emails still behave.

---

## Honest limitations

This tool is deliberately simple and rule-based. That means:

- It **cannot** say for certain whether an email is malicious. It only reports
  *warning signs* from a fixed checklist.
- A **low score does not prove an email is safe**, and a **high score is not proof**
  of an attack.
- It cannot see the true sender the way a mail server can, cannot check whether a
  link is live, and cannot analyse the contents of an attachment. It never opens,
  fetches or uploads anything.
- SPF / DKIM / DMARC results are only as good as the headers you paste. Those results
  are *reported*, not independently verified by this tool.

**Always** verify important or unexpected messages through an official website, app
or a phone number you already trust — never through the contact details in the email
itself. Never click links or open attachments just to test them.

---

## How to add your own rule (a nice first lesson)

Open `js/analyzer.js` and find the `RULES` list. Each rule is a small object. To add
one, copy this template and change the details:

```js
{
  id: "my_new_rule",
  label: "Short headline shown to the user",
  category: "My Category",
  weight: 10,                 // points added to the score
  severity: "medium",         // "high" | "medium" | "low" | "info"
  explain: "Why this matters, in plain English.",
  advice: "What the reader should do about it.",
  run: function (ctx) {
    // ctx.content is the email subject + body as text.
    return matchList(/\bmy phrase\b/gi, ctx.content, 6);  // or return null
  }
}
```

Then run the self-test to make sure nothing broke. That is the whole loop:
**notice a pattern → write a rule → add a test → run it.**

---

*Educational use only. Built with plain HTML, CSS and JavaScript.*

