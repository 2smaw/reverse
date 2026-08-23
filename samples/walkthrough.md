# Walkthrough: 6be287b7cd6746fbbf013eac0bd60507b929ab3691b4f4d7d302f25ea0e50a28
Hash: 6be287b7cd6746fbbf013eac0bd60507b929ab3691b4f4d7d302f25ea0e50a28
Suspected malware: mirai
Target: IoT
Architecture: MIPS, statically linked

— see [reading-decompiler-output.md](../../techniques/reading-decompiler-output.md)
for the general method this follows.

---

## 1. Socket setup block (found first, before `main` was fully mapped)

```c
LAB_00013264:
  if (uVar4 != 0) {
    puVar16 = (utsname *)socket(2,2,0);
    puVar20 = (utsname *)0xffffffff;
    *__buf = puVar16;
    if (puVar16 != (utsname *)0xffffffff) {
      setsockopt((int)puVar16,0xffff,4,__optval,4);
      local_44 = *__buf;
      uVar7 = fcntl((int)local_44,3,0);
      fcntl((int)local_44,4,uVar7 | 0x80);
      local_790.sysname[0] = '\0';
      local_790.sysname[1] = '\x02';
      local_790.sysname._4_4_ = htonl((uint32_t)pcVar19);
      uVar14 = htons(0xd312);
      local_790.sysname[2] = (char)(uVar14 >> 8);
      local_790.sysname[3] = (char)uVar14;
      iVar3 = bind((int)*__buf,(sockaddr *)local_48,0x10);
      puVar16 = *__buf;
      if (iVar3 != -1) goto LAB_000135cc;
      close((int)puVar16);
      *__buf = (utsname *)0xffffffff;
      goto LAB_000135bc;
    }
  }
```

**`socket(2,2,0)`** — domain `2` = `AF_INET`, type `2` = `SOCK_DGRAM`,
protocol `0` = default (UDP). Return value cast to `utsname *` is a
decompiler mistyping artifact (return type is really `int`, an fd) —
distrust the cast, not the API (see
[reading-decompiler-output.md](../../techniques/reading-decompiler-output.md) §2).

**`puVar16 != 0xffffffff`** — standard `!= -1` success check on the fd.

**`setsockopt(fd, 0xffff, 4, ...)`** — `SOL_SOCKET`/`SO_REUSEADDR`,
optlen 4 (an int-sized option) — the common
"allow rebind" idiom used before `bind()`.

**`fcntl` GETFL(3)/SETFL(4) pair, OR-ing `0x80`** — sets `O_NONBLOCK`.

**`local_790.sysname[...]` field writes** — decompiler flattened a
`sockaddr_in` into raw byte offsets inside a mistyped `utsname` struct.
Matched by offset against the real layout:
- bytes 0-1 (`'\0'`, `'\x02'`) -> `sin_family` = `AF_INET` (2)
- `._4_4_` (offset 4, size 4) via `htonl(pcVar19)` -> `sin_addr`
- bytes 2-3, high/low byte of `htons(0xd312)` -> `sin_port`

`0xd312` is already the argument *to* `htons`, i.e. it's the port in
host byte order = **54034 decimal**. (Corrected from an earlier
mis-statement during this analysis that treated it as needing an
additional byte-swap — always hand-check byte-order conversions rather
than assume.)

**`bind(fd, addr, 0x10)`** — `addrlen` 0x10 (16) matches
`sizeof(struct sockaddr_in)` exactly, confirming the struct guess.

**Outcome:** binds a UDP socket, non-blocking, `SO_REUSEADDR` set, to
port 54034 on an address derived from `pcVar19` (not yet traced back to
its origin — likely `INADDR_ANY` or a locally-resolved address, per
`util_local_addr()` seen later in `main` — not yet confirmed).
Documented as [hardcoded-port-bind.md](../../behaviors/c2-networking/hardcoded-port-bind.md).

---

## 2. Domain substring parsing (MIPS disassembly, `LAB_0001b32c`)

Found via a domain string (`atlassian.com`) located in Defined
Strings, sitting in a writable `.data` section (worth independent
follow-up — see open questions).

```
lw   t9, -0x7db8(gp) => ->strchr
sw   a0 => "atlassian.com", local_38(sp)
jalr t9 => strchr
_li  a1, 0x2e
lw   a0 => "atlassian.com", local_38(sp)
lw   gp, local_78(sp)
or   t0, v0, zero
bne  v0, zero, LAB_0001b370
_subu a2, v0, a0
lw   t9, -0x7da4(gp) => ->strlen
sw   a0 => "atlassian.com", local_38(sp)
jalr t9 => strlen
_sw  v0, local_34(sp)
lw   gp, local_78(sp)
lw   t0, local_34(sp)
lw   a0, local_38(sp)
or   a2, v0, zero
```

Reconstructed as C:
```c
char *dot = strchr("atlassian.com", '.');
size_t len;
if (dot != NULL) {
    len = dot - domain;        // delay slot of the branch — always runs
    goto LAB_0001b370;
} else {
    len = strlen("atlassian.com");
}
```

Key MIPS reading notes applied here: `t9` resolved via `gp`-relative
load to the GOT slot for `strchr`/`strlen`; `sw a0, local_38(sp)`
before each call is a spill (backup before the call clobbers
registers), reloaded via `lw a0, local_38(sp)` after; `or t0,v0,zero`
is the register-move idiom (`t0 = v0`); the pointer subtraction
`_subu a2,v0,a0` sits in the branch's delay slot and executes
unconditionally regardless of whether the branch is taken. `0x2e` is
ASCII `.`.

Documented as [domain-substring-matching.md](../../behaviors/c2-networking/domain-substring-matching.md).
**Not yet traced further** — what happens at `LAB_0001b370` with `len`
is an open question.

---

## 3. `main`'s setup sequence (top-level call list)

Full call list, in order, before the socket-setup block above:

```
table_init()
sigemptyset(&sStack_190)
sigaddset(&sStack_190, 2)               // SIGINT
sigprocmask(1, &sStack_190, NULL)       // block SIGINT
signal(0x12, SIG_IGN)                   // SIGCHLD ignored -> expect fork() later
signal(5, 0x4ed0)                       // SIGTRAP -> custom handler
signal(0xd, SIG_IGN)                    // SIGPIPE ignored -> standard for network code
hide_init()                             // see section 4 below
chdir("/")
prctl(1, 9)                             // PR_SET_PDEATHSIG, SIGKILL
prctl(4, 0)                             // PR_SET_DUMPABLE, disabled
prctl(0x26, 1, 0, 0, 0)                 // PR_SET_NAME (value arg unresolved)
open("/proc/self/oom_score_adj", O_WRONLY)
  write(fd, &UNK_00048ed0, 5)
  close(fd)
open("/proc/self/exe", O_RDONLY)
  close(fd)                             // no read in between — unresolved
rand_next()
  [~33% chance] rand_next(); sleep(rand % 120)
util_local_addr()
```

No argument parsing (`mainArg1`/`mainArg2`) touched before this entire
sequence — notable by absence; ordinary CLI programs typically parse
args or read config first.

Each behavior in this list mapped to its dictionary entry:
[anti-debug-sigtrap-handler.md](../../behaviors/evasion/anti-debug-sigtrap-handler.md),
[disable-core-dumps.md](../../behaviors/evasion/disable-core-dumps.md),
[sandbox-jitter-sleep.md](../../behaviors/evasion/sandbox-jitter-sleep.md),
[oom-score-immunity.md](../../behaviors/persistence/oom-score-immunity.md),
[pdeathsig-parent-tracking.md](../../behaviors/persistence/pdeathsig-parent-tracking.md),
[pr-set-name-spoofing.md](../../behaviors/process-hiding/pr-set-name-spoofing.md).

`signal(SIGCHLD, SIG_IGN)` is a useful forward-looking clue: this idiom
is only really used when the process expects to `fork()` children
repeatedly and doesn't want to reap zombies — worth watching for
`fork()`/`clone()` calls later in the binary.

---

## 4. `hide_init()`

```c
void hide_init(void) {
  int local_18[3];
  local_18[0] = 1;
  table_unlock_val(0x24);
  table_unlock_val(0x25);
  char *path = table_retrieve_val(0x24, 0);
  int fd = open(path, 2);
  if (fd == -1) {
    path = table_retrieve_val(0x25, 0);
    fd = open(path, 2);
    if (fd == -1) goto done;
  }
  ioctl(fd, 0x80045704, local_18);
  close(fd);
done:
  table_lock_val(0x24);
  table_lock_val(0x25);
}
```

`table_unlock_val`/`table_retrieve_val`/`table_lock_val` trio matches
the [obfuscated string table idiom](../../behaviors/anti-forensics/string-table-lock-unlock-obfuscation.md)
— paths at table slots `0x24`/`0x25` aren't visible in a static strings
dump.

Open-with-fallback-path pattern (`0x24` primary, `0x25` fallback on
failure) matches the classic pattern for a device file whose path
varies across systems — candidates: `/dev/watchdog`,
`/dev/misc/watchdog` (not yet confirmed by decoding the table).

`ioctl(fd, 0x80045704, &options)` with `options[0] = 1`: `0x80045704`
resolved against `<linux/watchdog.h>` as `WDIOC_SETOPTIONS`; value `1`
is `WDIOS_DISABLECARD`. **This disables the hardware watchdog timer**
— full reasoning and significance in
[watchdog-disable.md](../../behaviors/persistence/watchdog-disable.md).

**Corrected assumption:** the function name `hide_init` initially
suggested process/visibility hiding (matching the `PR_SET_NAME` call
seen in `main`). The actual code does something adjacent but distinct
— survivability/anti-recovery via watchdog disable, not concealment.
Function names are a hypothesis to verify, not a conclusion — see
[reading-decompiler-output.md](../../techniques/reading-decompiler-output.md) §8.

---

## Next steps

Continue breadth-first triage of `main`'s remaining calls per
[triage-workflow.md](../../techniques/triage-workflow.md), starting
with `table_init()` (to decode the string table) and tracing forward
from `util_local_addr()` and the post-`LAB_0001b370` domain-matching
code.
