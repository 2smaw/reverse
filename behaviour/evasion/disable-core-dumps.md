# Disabling Core Dumps (PR_SET_DUMPABLE)

**Category:** Evasion / Anti-Forensics
**Confidence:** Medium-High — legitimate daemons sometimes disable core
dumps for security (avoiding sensitive data leaking into a dump file),
but combined with other evasion behaviors it supports a malicious read.

## What it looks like in code

```c
prctl(4, 0);   // PR_SET_DUMPABLE, 0 = disabled
```

`prctl` option `4` is `PR_SET_DUMPABLE`. Setting it to `0` disables
core dump generation for the process.

## Why malware does this

If the process crashes, Linux would normally write a memory dump to
disk that a forensic analyst could inspect (recovering decrypted
strings, in-memory config, etc. that aren't visible in the static
binary). Disabling this removes that analysis path.

## How to recognize it

- `prctl(0x4, 0, ...)` or `prctl(PR_SET_DUMPABLE, 0, ...)` in
  decompiled output.
- Often appears near other `prctl` calls (e.g. `PR_SET_PDEATHSIG`,
  `PR_SET_NAME`) during process/daemon setup — worth reading the whole
  cluster of `prctl` calls together rather than in isolation.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)
