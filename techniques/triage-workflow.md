# Triage Workflow for an Unfamiliar Binary

A step-by-step approach for going from "a whole unfamiliar binary" to
"a short, prioritized list of functions actually worth reading in
full." Written for a breadth-first, evidence-driven process rather
than reading every function top to bottom (which doesn't scale).

## 1. Start from strings, not code

Pull the string table before touching any disassembly. Skim for
readable URLs, IPs, file paths, and suspicious-looking words. Each
interesting string has cross-references (xrefs) — jump to where it's
*used*. This turns "read the whole binary" into "read the handful of
functions that touch the strings that matter."

## 2. Check imports / recognized library calls in parallel

Scan for "loud" APIs relevant to the
[behavior dictionary](../behaviors/README.md) categories (networking,
process/exec, persistence-related `prctl`/`ioctl` calls, etc.). Each
also has xrefs. This is a second, independent entry point into "which
functions matter."

Note: a binary reporting **no imports** doesn't necessarily mean
imports were hidden — check whether it's simply statically linked
first (common for cross-compiled embedded/IoT malware). See
[glossary.md](../glossary.md).

## 3. Map main's top-level call structure — don't open anything yet

Open `main` (or the real entry point) in the decompiler and write down
every function call in the order it appears, ignoring everything else
(arithmetic, variable assignments, string contents). Note the control
flow shape around each call (inside an `if`? a loop? a `while(1)`?) —
an infinite-loop call is a strong candidate for the main event
loop/dispatcher.

## 4. Triage each call, breadth-first, one level at a time

For each function on the list:

1. **Is it a recognized library function** (or shaped like one — short,
   tight, matches a known algorithm)? If yes, skip its internals
   entirely; you already know what it does.
2. **Does its name give it away**, even partially? Weight this as a
   hypothesis, not a conclusion (see
   [reading-decompiler-output.md](./reading-decompiler-output.md) §8).
3. **List its own calls** (one level deep only, don't recurse yet) and
   bucket it:
   - Network (`socket`, `connect`, `bind`, `send`, `recv`,
     `gethostbyname`) — usually high priority
   - Process/exec (`fork`, `execve`, `system`, `clone`) — usually high
     priority
   - File I/O (`open`, `read`, `write`, `unlink`) — priority depends on
     *what's* being read/written
   - String/data manipulation only — usually supporting logic, skim
     rather than fully trace
   - No recognizable calls at all, mostly arithmetic/bitwise ops — flag
     as likely hand-rolled algorithm (encryption, checksum, hashing);
     worth flagging even before fully understanding it
   - Empty/trivial — deprioritize
4. **When ambiguous, use size and call-count as a tiebreaker.** Larger,
   more complex functions are more likely to hold real decision logic
   regardless of category.
5. **When genuinely unclear, defer rather than force a read.** Keep a
   "revisit later" list instead of fully reading something you can't
   yet categorize — momentum matters more than completeness on a first
   pass.

## 5. Repeat breadth-first, not depth-first

Triage everything `main` calls directly before diving deep into any one
branch. This avoids getting lost 8 functions deep in something that
turns out irrelevant, and keeps your mental map of the whole binary
growing evenly.

## 6. Only fully read (line-by-line) what triage flags as central

Reserve full reads for the small number of functions confirmed to
matter (C2 command dispatchers, encryption/decoding routines,
injection or persistence logic). Everything else stays at "skimmed,
looks like boilerplate" confidence unless something later contradicts
that.
