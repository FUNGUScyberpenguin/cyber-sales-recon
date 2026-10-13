---
name: slide-deck
description: Build a slide deck (.pptx) for a prospect from the research, on the user's brand template if they attach one in the chat. Use when the user asks for a deck, slides, or a presentation.
---

# Slide deck

Never show commands, file paths, tool names, or error traces in replies. Say the result in plain words.

## Before you start

1. Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then continue this request. Do not ask the user to repeat it.
2. Look for this chat's run: `find "$HOME/recon-work" -name bundle.json 2>/dev/null`. Use the one for the domain the user means. If the user means a different domain than the run, or the chat has no run, run the recon skill first, then come back here. A new chat has no run.
3. Read `bundle.json` and `snapshot.json` from that folder. Every claim about the prospect comes from a finding, its evidence, or a named, dated source. If the run or the profile lacks something, leave that claim out. No placeholders, no guesses.
4. A source listed under `not_checked` was not checked. Never describe it as clean or absent.

## Brand template

If the user attached a .pptx in this chat, use it as the template. If not, build on the default layout and say once that attaching a .pptx gives a branded deck. The template is never saved.

## Write the outline

Write `outline.json` in the run's folder. This is working detail: tell the user only that the deck is being built.

```json
{"title": "Title text", "subtitle": "Subtitle text",
 "slides": [{"title": "Slide title", "bullets": ["One claim per bullet"], "cites": ["finding-id-from-bundle"]}]}
```

- Eight slides or fewer, at most seven bullets each.
- Every slide with bullets cites the IDs of the findings behind it in `cites`. The IDs are used for the footer only. Never put an ID in slide text.
- Slides: what the research found, the findings that matter most (lead tier first), the recommended offering from the snapshot, and the firm and its offerings from the profile. Leave out any slide the run cannot support.
- Plain language for a buyer who is not an engineer.

## Build

Make sure the engine is installed (run the recon skill's `scripts/install_engine.py` if `reconbrief` is missing). Then:

```bash
reconbrief deck "$RUN/outline.json" --bundle "$RUN/bundle.json" --out "$RUN/DOMAIN-deck.pptx" [--template "PATH_TO_ATTACHED_PPTX"]
```

If it exits with 2, read the message, fix the outline, and run it again. Footers show source names and the run date. Give the user the .pptx file.
