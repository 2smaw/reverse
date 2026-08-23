# Domain Substring Matching (Dot-Delimited Parsing)

**Category:** C2 / Networking (supporting logic)
**Confidence:** Low-Medium on its own — this is a generic string
operation with many legitimate uses (subdomain parsing, config
handling); significance depends entirely on what the computed
substring/length is used for downstream.

## What it looks like in code (reconstructed from MIPS disassembly)

```c
char *dot = strchr(domain, '.');
size_t len;
if (dot != NULL) {
    len = dot - domain;          // length of substring before first '.'
} else {
    len = strlen(domain);        // whole string, no dot found
}
```

## Why this pattern matters

The `dot ? (dot - str) : strlen(str)` idiom isolates the portion of a
dotted string up to the first `.` — commonly used to split a hostname
into a leading label vs. the rest (`www.example.com` -> `www` +
`example.com`), often as a step in domain/allowlist comparison logic.

## How to recognize it (MIPS-specific notes)

- `strchr(str, 0x2e)` — `0x2e` is ASCII `.`.
- Pointer subtraction of the `strchr` result against the original
  string base, guarded by a `NULL`-check branch, with a `strlen` call
  in the fallback branch.
- Remember the MIPS delay-slot rule: the instruction right after a
  `bne`/branch still executes unconditionally — in the observed case,
  the pointer-subtraction (`len = dot - domain`) sits in the delay slot
  of the "dot found" branch and must not be misread as conditional.

## Why it's flagged here rather than dismissed

Found operating on a domain string (`atlassian.com`) sitting in a
writable `.data` section rather than read-only `.rodata` — worth
independently investigating why a literal domain string would need to
be writable (possible in-place decode/patch target). The domain itself
is a legitimate, well-known service, so the likely explanations are:
(a) legitimate allowlist/webhook-validation logic, (b) malware
checking network reachability to a well-known service for
reconnaissance, or (c) domain fronting / blending traffic against a
trusted host. Not yet resolved — see sample notes.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)

## Open questions

- What is `len` (and the string pointer) compared against immediately
  after this block? Not yet traced.
- Are there other domain strings clustered near this one in `.data`
  that would support the allowlist-matching hypothesis?
