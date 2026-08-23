# Reading Decompiler Output: General Method

A general method for turning noisy decompiler pseudocode into
something you can actually reason about, independent of architecture.

## 1. Anchor on function calls, not variable names

Decompiler-invented variable names (`uVar4`, `puVar16`, `local_790`)
carry no semantic weight — they're derived from register/stack usage.
Function calls, by contrast, are resolved symbols with known,
documented signatures. Always start there.

## 2. Distrust a cast that doesn't match the API it's touching

Decompilers sometimes mistype pointers based on size heuristics rather
than real usage (e.g. casting a socket file descriptor to
`struct utsname *` purely because the sizes happen to line up with
some other struct in a size table). If a cast's type doesn't
semantically fit the function it's passed to, trust the function's
real signature over the cast.

## 3. Look up unfamiliar constants, don't guess

Small integer constants passed to syscalls/library functions are
almost always `#define`d flags/options from a header (`socket.h`,
`fcntl.h`, `linux/watchdog.h`, etc.), not arbitrary numbers. Look them
up against the relevant header for the target platform rather than
assuming.

## 4. Recognize idioms as shapes, independent of variable names

- `x != -1` (or `!= 0xffffffff`) immediately after a syscall: success
  check.
- `fcntl(fd, F_GETFL, 0)` then `fcntl(fd, F_SETFL, flags | X)`:
  "add flag X" (X commonly `O_NONBLOCK` = `0x80`).
- `open()` with a fallback `open()` of a second path on failure: trying
  known alternate locations for the same logical resource (e.g. a
  device file that lives at different paths on different systems).
- `dot ? dot - str : strlen(str)`: extract the substring/length up to
  a delimiter.

## 5. Match raw offset writes against known structs

When a decompiler shows raw byte-level writes into a buffer about to
be passed to a network/syscall API (rather than clean struct field
assignments), align the offsets against the real struct layout for
that API (e.g. `sockaddr_in`: `sin_family`@0, `sin_port`@2,
`sin_addr`@4, total size 16). This recovers the real field meaning
even when the decompiler's type inference failed.

## 6. Cross-validate struct guesses against size literals

A `sizeof`-shaped literal nearby (e.g. `bind(fd, addr, 0x10)`) should
match your guessed struct's real size. If it doesn't, reconsider the
guess.

## 7. Merge decompiler-fragmented variables that are really one value

A value spilled to the stack and reloaded, or aliased through two
different pointers to the same buffer, should be treated (and later
renamed) as a single logical variable even though the decompiler shows
multiple names for it.

## 8. Treat function/symbol names as hypotheses, not conclusions

Auto-generated or even original developer-chosen names can be
misleading or only partially descriptive. Verify what a function
*actually does* against its code before trusting its name — and when
correcting a wrong assumption, note the correction explicitly rather
than silently fixing it. (Concrete example: a function named
`hide_init()` turned out to disable a hardware watchdog timer —
persistence/anti-recovery, not concealment. See
[watchdog-disable.md](../behaviors/persistence/watchdog-disable.md).)
