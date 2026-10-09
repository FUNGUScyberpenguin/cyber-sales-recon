# Opportunity Recon
- Read docs/SPEC.md before changing behavior. The work list is docs/PLAN.md. Do one task per session, with /next-task.
- Run the tests with `pytest` from the repo root.
- Public data only. Never add port scans, path brute force, form submission, input injection, or exploit checks.
- A failed lookup never produces a finding. Track found, absent, and unknown separately.
- Every request to a prospect host goes through the address guard (PLAN F3).
- Fixtures are recorded public-API responses or hand-written HTML in tests/fixtures/recorded/. Never test against live third-party sites.
- Keep firm-specific information out of the repo. No talk tracks, discovery questions, or testing disclaimers anywhere.
- After any change under reconbrief/, rebuild the vendored wheel with scripts/build_wheel.py (once F6 exists).
- Before using a plugin feature (userConfig, CLAUDE_PLUGIN_ROOT, CLAUDE_PLUGIN_DATA, skills), check the current docs at code.claude.com.
