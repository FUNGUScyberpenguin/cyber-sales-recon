---
name: next-task
description: Work the next unchecked task in docs/PLAN.md from plan to commit. Use only when the user runs /next-task.
disable-model-invocation: true
---
Work exactly one task from docs/PLAN.md. If the user gave a task ID ($ARGUMENTS), take that task. Otherwise take the first unchecked one.

1. Read docs/SPEC.md, docs/PLAN.md, and CLAUDE.md, then the code the task touches.
2. If the task is marked [Josh] and needs him to act before any code can change, tell him exactly what to do, then stop.
3. Plan: list the files you'll create or change, the failing test you'll write, and anything in the task that conflicts with the spec or the code. Ask Josh with AskUserQuestion about anything the task leaves open. Never put an open question into the product. Wait for approval.
4. Build: write the failing test and run it to show the failure. Make the change, run the full pytest suite, and show the summary. If anything under reconbrief/ changed and F6 is done, rebuild the vendored wheel.
5. Review: give the spec-reviewer agent the task ID. Fix every gap it reports that affects correctness, the done-when check, or a SPEC rule, then rerun the suite.
6. If the task has a [Josh] approval step, tell him exactly what to run in the app and what to look for, then stop before ticking the box.
7. Finish: tick the task in docs/PLAN.md, and add a one-line note under it if the approach changed. Commit everything with the message "<task ID>: <task title>". Report what changed, the final test summary, and the next unchecked task.
