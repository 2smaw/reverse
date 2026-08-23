# Custom SIGTRAP Handler (Anti-Debug)

**Category:** Evasion / Anti-Debugging
**Confidence signal:** Medium (common in Mirai-family IoT malware; also occasionally legitimate)

## What it looks like in code
`signal(SIGTRAP, <function_pointer>)` — installing a handler for signal 5
instead of leaving it default/ignored.

## Why malware does this
SIGTRAP fires on breakpoint/trap instructions, which debuggers rely on.
A custom handler can detect or interfere with an attached debugger.

## How to recognize it in decompiled/disassembled code
- Look for `signal(0x5, ...)` or `sigaction` with signum `5`
- The handler argument will be a real code address, not `SIG_IGN`(1)/`SIG_DFL`(0)

## Seen in
- [sample-2026-08-mips-XXXX](../samples/sample-2026-08-mips-XXXX/README.md)

## References
- 