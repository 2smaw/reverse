# OOM-Killer Immunity (oom_score_adj)

**Category:** Persistence / Anti-Recovery
**Confidence:** Medium — resource-sensitive legitimate daemons also
tune this value; combined with other survivability behaviors it's a
useful supporting signal, not a standalone verdict.

## what it looks like in code

```c
iVar3 = open("/proc/self/oom_score_adj", 1);  // O_WRONLY
if (iVar3 != -1) {
    write(iVar3, &SOME_STRING, 5);   // typically "-1000" or similar
    close(iVar3);
}
```

## why malware does this

Linux's OOM (out-of-memory) killer picks a process to kill when the
system runs critically low on memory, weighted by each process's
`oom_score`. Writing a very low value to `oom_score_adj` (commonly
`-1000`, the minimum, which makes the process effectively unkillable
by the OOM killer) protects the malicious process from being
terminated under memory pressure — improving its uptime/survivability
on resource-constrained devices (a relevant concern specifically on
IoT/embedded targets with limited RAM).

## how to recognize it

- `open("/proc/self/oom_score_adj", ...)` followed by a `write()` of a
  small numeric string.
- Check what string is actually written (resolve the referenced data)
  to confirm it's a low/negative value rather than something else.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/walkthrough.md)
