# Opportunity Recon

A Claude plugin for people who sell cybersecurity services. Give it a prospect's domain and it researches the company from public data, then helps you turn the results into a brief, a deck, outreach, and a scope outline.

It uses public data only.

## Install

In the Claude app:

1. Open Settings, then Plugins.
2. Add the marketplace `FUNGUScyberpenguin/cyber-sales-recon`.
3. Install `opportunity-recon`.

In Claude Code, run:

```
/plugin marketplace add FUNGUScyberpenguin/cyber-sales-recon
/plugin install opportunity-recon@cyber-sales-recon
```

## Set up (once)

Your first request starts setup on its own. You can also say "set up Opportunity Recon". It asks for your firm's website and drafts your firm profile from it: firm name, what you sell, how you scope or price, and what sets you apart. You confirm or fix the draft, and it saves the profile to Claude memory.

Setup also prints a block of text. Paste it into your Project instructions as a backup. To change your profile later, run setup again.

## Research a prospect

Say "research acme.com" or type `/recon acme.com`. Add the company name if the domain is a surprise ("research acme.com, Acme Holdings").

Claude installs the research engine, checks the network, runs, and shows a short snapshot: counts, the findings that matter most, the offering from your list that fits best, and any source it could not check. A source that failed is shown as "not checked". It never turns into a finding.

Nothing is stored between chats. Each run lives only in the chat where you made it. In a new chat, ask for the research again.

## Ask for outputs

After the snapshot, ask for any of these. If the chat has no run yet, Claude runs the research first.

- **Pre-call brief.** "Write a pre-call brief." One page of findings in plain language and the offering that fits.
- **Slide deck.** "Make a deck." Attach your brand .pptx in the chat if you want it on your template. It isn't stored.
- **Outbound drafts.** "Draft an email and a LinkedIn message." Short options grounded in what the run found.
- **Technical detail.** "Give me the technical detail." Hosts, services, certificates, and passive web-hygiene flags with evidence, for sales engineers.
- **Scope and proposal outline.** "Size this and outline a proposal." Sizing from the run's counts, built on your offerings and pricing basis.
- **Buying context.** "Why now?" Signals from your connected tools and web search, each with a named, dated source.

Every claim about a prospect traces to a finding or to a named, dated source. When your profile lacks a detail, Claude leaves the claim out.

## If your network blocks a run

Before each run, Claude checks that it can reach the public sources. If any are blocked, it names them and stops. Ask your IT team to allow HTTPS (port 443) to all of these hosts:

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

## License

MIT
