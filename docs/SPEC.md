# Opportunity Recon: product spec

## What it is
A public, firm-agnostic Claude plugin for people who sell cybersecurity services: account executives, SDRs and BDRs, sales engineers, and independent consultants. Anyone can install it from this repo into their own Claude account. A user gives Claude a prospect's domain. Claude runs the reconbrief engine over public data, saves the results, and shows a short snapshot. The user then asks Claude for whatever they need from those results.

## How a user works with it
1. Install the plugin from this repo's marketplace into their own Claude.
2. First use runs a one-time setup that captures a firm profile: firm name, firm website, the user's role, the offerings they sell (mapped to engine lenses), how they scope or price (optional), their differentiators, and an optional brand .pptx. The profile lives in the user's own Claude and never in this repo. Rerunning setup changes it.
3. Recon: "research acme.com" or /recon acme.com. Claude installs the engine from the plugin, runs preflight, runs the engine, saves the run, and shows the snapshot. The snapshot covers counts, the findings that matter most, any source that failed, and a list of outputs the user can ask for next.
4. Outputs on request, each built from the saved run plus the firm profile:
   - Pre-call brief: findings in plain language, buying context if gathered, and the recommended offering, chosen from the user's own list.
   - Slide deck: Claude writes the outline, and the engine builds the .pptx on the user's brand template when one exists.
   - Outbound drafts: short email and LinkedIn options grounded in observed signals.
   - Technical detail: hosts, services, certificates, and evidence, plus an evidence export in JSON and CSV.
   - Scope and proposal outline: sizing from the scoping counts, and an engagement outline from the user's offerings and pricing basis.
   - Buying context: why-now signals from the user's connected tools and web search, each with a named, dated source.
   If no saved run exists for the domain, the output skill runs recon first.

## Product rules
- Every claim about a prospect traces to a finding or evidence ID from the run, or to a named, dated source.
- Never invent firm details. If the profile lacks something, leave that claim out. No placeholders in outputs.
- The engine reads public data only. No port scans, wordlist or path brute force, form submission, input injection, or exploit checks.
- No scripted talk tracks, discovery questions, guidance on what to tell prospects, or disclaimers about testing, in any output or doc.
- The repo contains no information about any specific firm.

## Engine requirements
These come from a review of an earlier version, which got each one wrong.
- Every check has three states: found, absent, unknown. A failed or timed-out lookup is unknown, produces no finding, and shows as "not checked."
- DNS retries timeouts and truncated answers over TCP. The earlier version reported "no SPF record" for a domain whose 40 TXT records timed out over UDP.
- Every HTTP request to a prospect host goes through one guard that resolves the host and allows only addresses where ipaddress.ip_address(a).is_global is true. The client connects to the checked address (hostname kept for SNI and Host) and follows redirects manually through the same guard. Hosts that resolve only to non-global addresses get a background finding, "internal addresses published in public DNS," and never count as reachable from the internet.
- RDAP status strings are normalized (lowercase, spaces, hyphens, and underscores removed) before matching. RDAP returns "client transfer prohibited" with spaces.
- Login portal and product detection uses strong signals: page title, password forms, the login path actually loaded, product headers or cookies, and favicon hashes. A product name in body text is never enough on its own.
- Certificate details come from getpeercert(binary_form=True) parsed with cryptography, so expired and self-signed certificates are recorded even when verification fails. Verify errors are classified as expired, self-signed, untrusted issuer, or hostname mismatch.
- Wildcard DNS is checked before any hostname gets priority. A wildcard host counts as live only if its page differs from the wildcard response.
- Non-production hostname words are split into strong (dev, staging, stg, uat, qa, test, preprod) and weak (demo, beta, old, lab, pilot, canary). Weak words need a page signal before they count.
- Microsoft 365 service names (autodiscover, lyncdiscover, enterpriseregistration, enterpriseenrollment, msoid, sip) that CNAME to Microsoft never produce portal or certificate findings.
- Company matching uses trusted names only: the user's hint, og:site_name, and an unredacted RDAP registrant org. An entity from GLEIF or EDGAR is accepted only when a second signal (its registered domain, or its city) agrees.
- Version-banner vulnerability findings are capped at ask level, and at background for distributions that backport fixes (Red Hat, Debian, Ubuntu, SUSE), unless a CISA KEV entry matches. NVD results are paged in full.
- Trust-center absence is reported only when the trust-center source ran. Vendor and certification patterns use word boundaries (the earlier "vanta" pattern matched "advantage"). A candidate page whose body hash or title matches the homepage is a soft 404.
- AI exposure counts only script sources, API endpoints, and widget markup, never a vendor name in page text.
- Every source records health: ok, partial, failed, or skipped. Failures show in the snapshot.
- Preflight requires every core host. A 403, a 407, or a response with proxy headers counts as blocked.
- The opt-in crawl fetches and honors robots.txt for every origin it visits, including * and $ patterns.
- Findings carry no talk tracks or questions.

## Defaults (decided October 9, 2026)
- Contact depth: web, which loads the root page of up to 50 live hosts. Other levels: none (third-party data only), dns, and crawl (opt-in).
- urlscan.io stays on the default path.
- The opt-in crawl collects published email addresses on the prospect's domains.
- Trust pages are found from homepage links, trust. and security. hosts found in discovery, and /.well-known/security.txt. No other guessed paths.
- The User-Agent names the tool, its version, and this repo's URL.
- Offerings map to six lenses: external-pentest, web-app-api, continuous-exposure-management, red-team, ai-red-teaming, vciso-program-review.

## Architecture
- reconbrief/: the Python engine (3.11+). Sources write evidence, rules turn evidence into findings, and every finding cites its evidence. `reconbrief run` writes bundle.json, snapshot.json, and evidence.csv. `reconbrief deck` renders a validated outline to .pptx.
- plugins/opportunity-recon/: the plugin, with skills for setup, recon, and each output. vendor/ holds the engine wheel, which is installed by exact path and never by name.
- .claude-plugin/marketplace.json: the public marketplace entry.

## Not in scope for v1
A hosted service, org-wide admin rollout, a no-engine web version, firm content in the repo, keyed data sources (Shodan and the like), and breach-notification registers.
