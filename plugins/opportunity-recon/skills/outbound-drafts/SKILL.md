---
name: outbound-drafts
description: Draft short cold email and LinkedIn message options for a prospect, grounded in what the research found. Use when the user asks for outreach, an email, a LinkedIn message, or outbound copy.
---

# Outbound drafts

Never show commands, file paths, tool names, or error traces in replies. Say the result in plain words.

## Before you start

1. Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then continue this request. Do not ask the user to repeat it.
2. Look for this chat's run: `find "$HOME/recon-work" -name bundle.json 2>/dev/null`. Use the one for the domain the user means. If the user means a different domain than the run, or the chat has no run, run the recon skill first, then come back here. A new chat has no run.
3. Read `bundle.json` and `snapshot.json` from that folder. Every claim about the prospect comes from a finding, its evidence, or a named, dated source. If the run or the profile lacks something, leave that claim out. No placeholders, no guesses.
4. A source listed under `not_checked` was not checked. Never describe it as clean or absent.

## Write the drafts

Ask who the message goes to (name and title) only if the user has not said. Never invent a person.

Write three email options and two LinkedIn message options.

- Emails: a subject line and a body under 90 words. LinkedIn: under 60 words.
- Each draft opens with one specific observation from a finding, in plain words. A busy executive must understand it without a security background.
- Each draft names the firm and ties to one offering from the profile. Use only offerings and differentiators the profile lists.
- Under each draft, one line names the finding or source it rests on.
- Do not claim the prospect was breached or is vulnerable. Report only what the run observed from public data, and say it that way.
- Do not invent customers, results, numbers, or mutual connections.
- No placeholders in brackets. If a detail is missing, leave the sentence out.

Show the drafts in the chat. The user sends them. Do not send or save anything.
