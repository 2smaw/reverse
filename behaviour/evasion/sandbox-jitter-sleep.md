# Randomized Startup Sleep / Jitter

**Category:** Evasion / Sandbox Evasion
**Confidence:** Medium — random delays have legitimate uses too (e.g.
avoiding thundering-herd reconnects), but a probability-gated sleep
right at startup, before any real work happens, leans malicious.

## What it looks like in code

```c
uVar4 = rand_next();
if (uVar4 % 3 == 0) {         // ~33% chance
    uVar4 = rand_next();
    sleep(uVar4 % 0x78);       // sleep up to 120 seconds
}
```

## Why malware does this

Automated malware sandboxes typically run a sample for a limited
window (seconds to a couple minutes) before concluding analysis.
Randomized delays, especially probability-gated ones, are used to:
- Avoid exhibiting "real" behavior inside that analysis window.
- Desynchronize behavior across many infected hosts (e.g. so an entire
  botnet doesn't beacon to C2 at the same instant).

## How to recognize it

- A call to a PRNG function near process start, gating a `sleep()`
  call behind a modulo/probability check.
- Often appears before any network/file activity, i.e. very early in
  `main`.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)
