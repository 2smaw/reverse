# Process Name Spoofing (PR_SET_NAME)

**Category:** Process Hiding
**Confidence:** Low-Medium in isolation (many legitimate programs set
a friendly process name); higher confidence if the name set is a known
decoy (e.g. mimicking a kernel thread or common system process name)
rather than the program's own identity.

## What it looks like in code

```c
prctl(0x26, name_ptr, 0, 0, 0);   // PR_SET_NAME
```

`prctl` option `0x26` (38 decimal) is `PR_SET_NAME` — sets the value
visible in `ps`/`/proc/[pid]/comm` for this process.

## Why malware does this

Renaming the process to something innocuous or system-looking (e.g.
`[kworker/0:1]`, `cron`, `udevd`) helps it blend into a normal process
listing, making casual inspection (`ps`, `top`) less likely to reveal
it as suspicious.

## How to recognize it

- `prctl(0x26, ...)` calls.
- Check what value is actually passed as the name — if it's a single
  fixed benign-sounding string, or picked from a small table of decoy
  names (possibly tied to a string-obfuscation table — see
  [string table lock/unlock](../anti-forensics/string-table-lock-unlock-obfuscation.md)),
  that supports the spoofing read over an innocent "give my daemon a
  label" use.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)
  (call observed; actual name value not yet resolved — open question)
