# Behavior Dictionary

A sample-agnostic reference of malware behaviors/idioms recognized
during analysis. Each entry describes what a pattern looks like in
code, why malware does it, how to recognize it, and (over time) which
samples in this repo exhibit it.

## Index

### Evasion
- [Custom SIGTRAP handler (anti-debug)](./evasion/anti-debug-sigtrap-handler.md)
- [Disabling core dumps (PR_SET_DUMPABLE)](./evasion/disable-core-dumps.md)
- [Randomized startup sleep / jitter](./evasion/sandbox-jitter-sleep.md)

### Persistence / Anti-Recovery
- [OOM-killer immunity (oom_score_adj)](./persistence/oom-score-immunity.md)
- [PDEATHSIG parent-death tracking](./persistence/pdeathsig-parent-tracking.md)
- [Hardware watchdog disable](./persistence/watchdog-disable.md)

### Process Hiding
- [Process name spoofing (PR_SET_NAME)](./process-hiding/pr-set-name-spoofing.md)

### Anti-Forensics
- [Encoded string table lock/unlock](./anti-forensics/string-table-lock-unlock-obfuscation.md)

### C2 / Networking
- [Hardcoded port bind (UDP listener setup)](./c2-networking/hardcoded-port-bind.md)
- [Domain substring matching (dot-delimited parsing)](./c2-networking/domain-substring-matching.md)

## How entries are structured

Each entry follows the same template: what it looks like in code, why
malware does it, how to recognize it in disassembly/decompiler output,
a confidence note (since some idioms are also used in legitimate
software), and links to samples where it was observed.
