---
name: scope-proposal
description: Size the work from the run's counts and outline a proposal built from the user's own offerings and pricing basis. Use when the user asks for scope, sizing, a proposal outline, or an estimate of effort.
---

# Scope and proposal outline

## Before you start

1. Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then continue this request. Do not ask the user to repeat it.
2. Look for this chat's run: `find "$HOME/recon-work" -name bundle.json 2>/dev/null`. Use the one for the domain the user means. If the user means a different domain than the run, or the chat has no run, run the recon skill first, then come back here. A new chat has no run.
3. Read `bundle.json` and `snapshot.json` from that folder. Every claim about the prospect comes from a finding, its evidence, or a named, dated source. If the run or the profile lacks something, leave that claim out. No placeholders, no guesses.
4. A source listed under `not_checked` was not checked. Never describe it as clean or absent.

## Size from the run

Use the counts in `snapshot.json`: hostnames found, live hosts, web pages loaded, and findings by tier. State the counts exactly, with the run date. They describe what public data showed, not the full environment, so say that scope is confirmed with the prospect.

## Outline the proposal

- Start from the `recommendation` in the snapshot. Use only offerings listed in the profile, by their names.
- For each offering in the outline, say which counts and findings support it.
- Pricing: use the profile's pricing basis. If it says "not given", write the sizing drivers (host count, web applications, and so on) and do not state a price, a day rate, or a number of days.
- Lay out the proposal sections: background, objectives, scope, approach, deliverables, assumptions, and next steps. Fill each from the run and the profile. Leave out a section the data cannot support.
- Do not invent the firm's methods, team, timelines, or past clients.

Show the outline in the chat. Offer a .docx only if the user asks.
