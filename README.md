<p align="center"><img src="assets/banner.svg" alt="Opportunity Recon: walk into every call knowing the company" width="100%"></p>

Tell Claude who you're meeting. It researches the company from public information and gets you ready.

<img src="assets/steps.svg" alt="Install, set up once, just ask" width="100%">

## Install

1. In the Claude app, open **Settings**, then **Plugins**.
2. Add the marketplace `FUNGUScyberpenguin/cyber-sales-recon`.
3. Install **opportunity-recon**.

Use it inside a Claude Project. Your firm profile and your habits stay with your work there.

## Set up once

Your first request starts setup. Give Claude your firm's website. It drafts your profile, you fix anything that's off, and it remembers. Paste the backup text it prints into your Project instructions.

## Then just ask

Talk the way you would to a coworker. Say who you're meeting.

<img src="assets/chat.svg" alt="Example chat: a salesperson asks to be ready for a call with acme.com and gets a short snapshot with next steps" width="100%">

You don't need commands. If you only know the company's name, Claude asks for its website.

## What you can ask for

<img src="assets/outputs.svg" alt="Six things you can ask for" width="100%">

Every claim traces back to something the research found, or to a named, dated source. If your profile is missing a detail, Claude leaves that claim out.

Nothing is stored between chats. Each run lives in the chat where you made it. In a new chat, ask again.

<details>
<summary><strong>Research blocked? Send this to your IT team.</strong></summary>

<br>

Before each run, Claude checks that it can reach the public sources. If any are blocked, it names them and stops. Ask your IT team to allow HTTPS (port 443) to these hosts:

```
rdap.org
crt.sh
api.certspotter.com
web.archive.org
urlscan.io
login.microsoftonline.com
stat.ripe.net
ip-ranges.amazonaws.com
www.gstatic.com
www.cloudflare.com
www.cisa.gov
services.nvd.nist.gov
www.wikidata.org
api.gleif.org
www.sec.gov
data.sec.gov
```

The run also needs to reach the prospect's own public websites and DNS.

The web-hygiene check is optional. It needs Java 17 or newer and a one-time download from `github.com` and the GitHub release file hosts (`objects.githubusercontent.com`, `release-assets.githubusercontent.com`). If either is unavailable, that one source is reported as "skipped" and the run finishes without it.

A 403 or 407 from your network, or a proxy page in place of the real answer, counts as blocked.

</details>

MIT license.
