# Encoded String Table Lock/Unlock

**Category:** Anti-Forensics / String Obfuscation
**Confidence:** High — this lock/unlock/retrieve trio is a distinctive
custom idiom rarely seen outside deliberate string-hiding schemes.

## What it looks like in code

```c
table_unlock_val(0x24);
table_unlock_val(0x25);
val = table_retrieve_val(0x24, 0);
// ... use val ...
table_lock_val(0x24);
table_lock_val(0x25);
```

A "table" of values (populated once, early, by an init routine — e.g.
`table_init()`) is unlocked (decoded in place, commonly via XOR) right
before use, read by index, and re-locked (re-encoded) immediately
after.

## Why malware does this

Keeps sensitive strings (device paths, C2 domains/IPs, file paths)
out of plaintext in the binary's static data, defeating simple
`strings`-based static analysis. Only briefly decoded in memory around
its point of use, minimizing the window where it's visible even to
memory-scanning tools.

## How to recognize it

- A cluster of three related custom (non-libc) functions used
  together: an init/populate function called once at startup, and a
  lock/unlock/retrieve trio used around every access to encoded data.
- Absence of an expected plaintext string in a static strings dump
  where context (e.g. an `open()` call, a `connect()` call) strongly
  implies a string argument should exist.
- To read the real value: locate and reverse the decode routine (used
  by `table_init()`/`unlock`), or inspect memory at runtime
  (breakpoint/watch right after the `retrieve` call, or emulate).

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)
  (used to store watchdog device paths, slots `0x24`/`0x25` —
  plaintext values not yet decoded)

## Open questions

- Have not yet located/reversed `table_init()`'s decode algorithm.
- Unknown how many total slots exist in the table or what else is
  stored in it (likely additional paths, and possibly the C2 domain
  found in `.data`, if that turns out to be table-managed too rather
  than a plain static string — worth checking).
