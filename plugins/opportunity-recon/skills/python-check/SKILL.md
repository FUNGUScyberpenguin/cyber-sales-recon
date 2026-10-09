---
description: Throwaway plumbing test. Prints the Python version and where the plugin keeps files. Use only when asked to run the Opportunity Recon python check.
---

# Python check

Run this with the Bash tool and show the output as-is:

```bash
python3 -c "import sys, platform; print(sys.version); print(platform.machine())"
```

Then print these two paths exactly as Claude Code resolved them:

- Plugin folder: ${CLAUDE_PLUGIN_ROOT}
- Plugin data folder: ${CLAUDE_PLUGIN_DATA}

Finally, create a file named `check.txt` in the plugin data folder containing the text `ok`, read it back, and say whether it worked.
