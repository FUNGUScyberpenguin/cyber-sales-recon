---
name: setup
description: One-time setup for Opportunity Recon. Saves the user's firm profile (firm, role, offerings, pricing basis, differentiators) to Claude memory. Use on first use, when any Opportunity Recon skill finds no profile, or when the user asks to set up or change their profile.
---

# Set up Opportunity Recon

The profile tells every other skill who the user sells for and what they sell. It never goes in the repo and never leaves the user's own Claude.

## 1. Look for an existing profile

Search memory for "Opportunity Recon firm profile". Use project memory when this chat is inside a project, general memory otherwise. If a profile exists, show it in a few lines and ask what to change. Update only those fields.

## 2. Ask for the profile

Ask one question at a time, in plain words. Skip anything the user already said.

1. Firm name.
2. Firm website.
3. Their role (account executive, SDR or BDR, sales engineer, consultant, other).
4. What the firm sells. One line per offering, in the user's own words.
5. How they scope or price, if they want to say. This is optional. Skip it if they pass.
6. What sets the firm apart, in a sentence or two.

Do not ask for a brand template here. Say once that for a deck, they attach their .pptx in the chat when they ask for it. A project keeps only text, so the template is never stored.

Never invent an answer. A field the user skips stays empty.

## 3. Map offerings silently

For each offering, pick one or more of these six categories: external-pentest, web-app-api, continuous-exposure-management, red-team, ai-red-teaming, vciso-program-review. Never show lens names or ask the user to choose them. If an offering fits none, keep it with an empty list.

## 4. Save to memory

Save one memory entry that starts with the heading "Opportunity Recon firm profile". Use this layout:

```
Opportunity Recon firm profile
Firm: <name>
Website: <url>
Role: <role>
Pricing basis: <text or "not given">
Differentiators: <text or "not given">
Offerings:
- <offering name> | <lens>, <lens>
```

Save it to project memory when inside a project, general memory otherwise. If memory is not available in this chat, say so and rely on the backup in step 5.

## 5. Show the backup

Show the same text again in one code block, with this line above it: "Paste this into your Project instructions as a backup." Say that is the only copy kept outside memory.

## 6. Finish

Say setup is done in one line. If the user came here from another request, continue that original request now.
