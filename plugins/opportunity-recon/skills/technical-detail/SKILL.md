---
name: technical-detail
description: Give a sales engineer a readable summary of the research: hosts, services, certificates, passive web-hygiene flags, and evidence. Use when the user asks for technical detail, the evidence behind a finding, or what the run saw on specific hosts.
---

# Technical detail

## Before you start

1. Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then continue this request. Do not ask the user to repeat it.
2. Look for this chat's run: `find "$HOME/recon-work" -name bundle.json 2>/dev/null`. Use the one for the domain the user means. If the user means a different domain than the run, or the chat has no run, run the recon skill first, then come back here. A new chat has no run.
3. Read `bundle.json` and `snapshot.json` from that folder. Every claim about the prospect comes from a finding, its evidence, or a named, dated source. If the run or the profile lacks something, leave that claim out. No placeholders, no guesses.
4. A source listed under `not_checked` was not checked. Never describe it as clean or absent.

## Write the summary

Read `bundle.json` and write a readable summary with these sections. Skip a section the run has nothing for.

- **Hosts.** Live hosts first, then other hostnames found. Note the address class when the run records one.
- **Services and software.** Login portals, products, tech stack, banners, and API docs, each with its host.
- **Certificates.** Issuer, expiry, self-signed or expired status, and names, by host.
- **Email and DNS.** SPF, DMARC, DKIM, MTA-STS, CAA, and registration findings.
- **Passive web hygiene.** Flags from the OWASP ZAP passive scan and the engine's header checks. Say these came from passive analysis of pages already fetched.
- **Evidence.** For each finding, its evidence ID, source, and observation time.
- **Not checked.** Each source that failed, was skipped, or returned unknown, by name.

Write sentences and short tables, not a dump. Do not export raw bundle data or write a data file. Report found, absent, or not checked for each check, and never turn an unknown into a finding.
