# Hardware Watchdog Disable

**Category:** Persistence / Anti-Recovery
**Confidence:** High when combined with encoded/obfuscated device
paths and no legitimate watchdog-management context — this is a
well-documented, specific behavior in the Mirai malware family.

## What it looks like in code

```c
// path resolved from an obfuscated string table, with a fallback path
fd = open(primary_path, O_RDWR);
if (fd == -1) {
    fd = open(fallback_path, O_RDWR);
    if (fd == -1) goto done;
}
options = 1;                          // WDIOS_DISABLECARD
ioctl(fd, 0x80045704, &options);      // WDIOC_SETOPTIONS
close(fd);
```

`0x80045704` is `WDIOC_SETOPTIONS` from `<linux/watchdog.h>`; option
value `1` is `WDIOS_DISABLECARD`.

## Why malware does this

Many embedded/IoT Linux devices have a hardware watchdog timer: if not
periodically "kicked" by a supervising process, the hardware forces a
reboot — a safety mechanism to recover a hung device. Malware that
lives only in RAM (not persisted to flash/disk) is wiped by such a
reboot. Explicitly disabling the watchdog (`WDIOS_DISABLECARD`) removes
this automatic recovery path, letting the infection persist across
what would otherwise be a self-healing reboot.

## How to recognize it

- A device-open-with-fallback-path pattern (trying one path, falling
  back to an alternate on failure) followed by an `ioctl()` call.
- Resolve the ioctl request constant against `<linux/watchdog.h>` —
  `0x80045704` (`WDIOC_SETOPTIONS`) is the one to know by sight.
- Common candidate paths to expect once decoded: `/dev/watchdog`,
  `/dev/misc/watchdog`.
- If strings are obfuscated (see
  [string table lock/unlock](../anti-forensics/string-table-lock-unlock-obfuscation.md)),
  the actual path won't be visible in a static string dump — needs
  runtime/decoded inspection to confirm.

## Correcting an initial assumption

This behavior was found inside a function named `hide_init()` in the
observed sample. The name suggested process/visibility hiding, but the
actual code disables the hardware watchdog instead — a
persistence/anti-recovery behavior, not concealment. **Lesson: treat
function names (auto-generated or original) as a hypothesis to verify
against the actual code, not a conclusion.**

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)

## References

- Consistent with documented Mirai-family watchdog-disable behavior
  (worth cross-referencing against leaked Mirai source for exact
  constant/path match once confirmed).
