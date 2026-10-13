---
name: precall-brief
description: Write a one-page pre-call brief for a prospect. Findings in plain language plus the recommended offering from the user's own list. Use when the user asks for a written one-page brief, a call prep document, or a summary of what the research found. A plain request to get ready for a call starts with the recon skill, which then offers this brief.
---

# Pre-call brief

Never show commands, file paths, tool names, or error traces in replies. Say the result in plain words.

## Before you start

1. Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then continue this request. Do not ask the user to repeat it.
2. Look for this chat's run: `find "$HOME/recon-work" -name bundle.json 2>/dev/null`. Use the one for the domain the user means. If the user means a different domain than the run, or the chat has no run, run the recon skill first, then come back here. A new chat has no run.
3. Read `bundle.json` and `snapshot.json` from that folder. Every claim about the prospect comes from a finding, its evidence, or a named, dated source. If the run or the profile lacks something, leave that claim out. No placeholders, no guesses.
4. A source listed under `not_checked` was not checked. Never describe it as clean or absent.

## Write the brief

Keep it to one page. Use these sections:

- **Who they are.** Company name and domain, from the run's company evidence. Include only what the run found.
- **What the research found.** The findings that matter most, lead tier first, in plain language a non-engineer follows. One or two sentences each. Cite the finding ID in brackets after each claim, for example [rule:key].
- **Recommended offering.** The `recommendation` in the snapshot, by the offering's name from the profile, with the findings behind it. If the snapshot has none, say the run did not point to one of the user's offerings, and stop there.
- **Not checked.** Each entry under `not_checked`, by source name.

Use the firm's differentiators only where a finding connects to one. Quote the profile's wording and call it the firm's own claim. Do not add advice on what to say to the prospect, and do not add questions to ask.

Show the brief in the chat. Offer it as a .docx only if the user asks for a file.
