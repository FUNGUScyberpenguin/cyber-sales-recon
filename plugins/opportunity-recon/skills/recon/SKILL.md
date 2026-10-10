---
name: recon
description: Research a prospect company from public data. Use when the user says "research acme.com", gives a domain to look into, or runs /recon. Installs the engine, runs it, and shows a short snapshot of findings, then asks which outputs to make.
argument-hint: acme.com
---

# Recon a prospect

## 1. Check the profile

Search memory for "Opportunity Recon firm profile" (project memory in a project, general memory otherwise). If it is missing, run the setup skill first, then come back here and continue the original request. Do not ask the user to repeat it.

## 2. Get the domain

Take the domain from the request or from the argument. Accept a URL and trim it to the domain. If the user gave a company name too, keep it as the company hint. If there is no domain, ask for one.

## 3. Find this skill's folder

No path variables are set in chat or Cowork. Find the folder with `find`:

```bash
SKILL_DIR=$(dirname "$(find / -path "*opportunity-recon*/skills/recon/SKILL.md" -not -path "/proc/*" 2>/dev/null | head -1)")
WORK="$HOME/recon-work"; mkdir -p "$WORK"
python3 "$SKILL_DIR/scripts/install_engine.py"
```

The script installs the wheel in `$SKILL_DIR/vendor/` by file path. If it fails, tell the user in one line and stop.

## 4. Write the engine's profile file

Write `$WORK/profile.json` from the memory entry. Use only the offerings the user gave, with their categories:

```json
{"offerings": [{"name": "External penetration testing", "lenses": ["external-pentest"]}]}
```

Leave out offerings with an empty category list. If none remain, skip `--profile` in step 6.

## 5. Check the network

```bash
reconbrief preflight
```

If it exits with 3, show which hosts are blocked or not reachable, say the network stops the run, and stop. Do not try to work around it.

## 6. Run the engine

```bash
reconbrief run DOMAIN --out "$WORK/DOMAIN" --data-dir "$WORK/data" --profile "$WORK/profile.json" [--company "NAME"]
```

It writes `bundle.json` and `snapshot.json` into `$WORK/DOMAIN`. These files stay in this chat's sandbox. There is no saved run: a new chat runs the research again.

## 7. Show the snapshot

Read `snapshot.json` and show a short summary:

- Counts: hostnames found, live hosts, findings by tier.
- The top findings, one line each, in plain language.
- The recommended offering, if the snapshot has one, with the findings behind it.
- Every entry under `not_checked`, listed as "not checked", with its source name. A source that did not run is never a finding.

State only what the snapshot says. Do not guess about the prospect or the firm.

## 8. Ask what next

Ask which outputs to make, or whether the user has other questions or wants more research. The outputs are: pre-call brief, slide deck, outbound drafts, technical detail, scope and proposal outline, and buying context. Say a deck needs the brand .pptx attached in the chat. Outputs come back as files or text in this chat.
