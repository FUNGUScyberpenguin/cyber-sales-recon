---
description: Throwaway plumbing test. Prints the Python version and checks where project files and saved files show up. Use only when asked to run the Opportunity Recon python check.
---

# Python check

Path variables are not set in every app, so find the script first:

```bash
SCRIPT=$(find / -path "*opportunity-recon*/python-check/scripts/probe.py" 2>/dev/null | head -1)
python3 "$SCRIPT"
```

Show the full output as-is.
