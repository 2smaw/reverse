# PDEATHSIG Parent-Death Tracking

**Category:** Persistence / Process Supervision
**Confidence:** Low-Medium on its own — this is a very common, largely
benign idiom in legitimate child-process management; only notable when
clustered with other evasion/persistence behaviors.

## What it looks like in code

```c
prctl(1, 9);   // PR_SET_PDEATHSIG, SIGKILL
```

`prctl` option `1` is `PR_SET_PDEATHSIG`; the second argument is the
signal to deliver to this process if its parent dies — `9` is
`SIGKILL`.

## Why malware does this

Ensures the process cleanly terminates if its parent (e.g. a launcher
or dropper process) dies unexpectedly, rather than becoming an orphan
in an unexpected state. Used both in legitimate process supervision and
in malware to keep process trees tidy/predictable.

## How to recognize it

- `prctl(0x1, <signum>, ...)` early in process startup, often alongside
  `PR_SET_DUMPABLE` and `PR_SET_NAME`.

## Seen in

- [sample-2026-6be287b7cd6746fbbf013eac0bd60507b929ab3691b4f4d7d302f25ea0e50a28](../../samples/6be287b7cd6746fbbf013eac0bd60507b929ab3691b4f4d7d302f25ea0e50a28.md)