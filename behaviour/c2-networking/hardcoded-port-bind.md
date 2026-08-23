# Hardcoded Port Bind (UDP Listener Setup)

**Category:** C2 / Networking
**Confidence:** Medium alone (plenty of legitimate services bind fixed
ports); higher when the port has no config/CLI source and is baked
directly into the binary, and higher still when clustered with other
behaviors in this dictionary.

## What it looks like in code

```c
sock = socket(AF_INET, SOCK_DGRAM, 0);       // 2, 2, 0
setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, 4);
flags = fcntl(sock, F_GETFL, 0);
fcntl(sock, F_SETFL, flags | O_NONBLOCK);    // 0x80

struct sockaddr_in addr;
addr.sin_family = AF_INET;                   // 2
addr.sin_port   = htons(FIXED_PORT);
addr.sin_addr   = htonl(bind_ip);
bind(sock, (struct sockaddr*)&addr, sizeof(addr));  // 0x10 = 16
```

Note: decompilers frequently mis-type this struct (e.g. as an
unrelated struct like `utsname` purely because it happens to be a
similar size) and show the fields as raw byte/offset writes instead of
named struct members. Match offsets against the real `sockaddr_in`
layout (`sin_family` @0, `sin_port` @2, `sin_addr` @4, size 16) to
recover the real meaning — see
[reading-decompiler-output.md](../../techniques/reading-decompiler-output.md).

## Why malware does this

Standard setup for either a local listener (backdoor waiting for
inbound connections/commands) or transport used elsewhere for
outbound communication. `SO_REUSEADDR` + non-blocking mode are
consistent with a long-running service that wants to rebind quickly
after restart and not block its main loop on I/O — suggests this feeds
into an event loop (`select`/`poll`/`epoll`) elsewhere in the binary,
worth tracing forward to confirm.

## How to recognize it

- `socket(2, 2, 0)` = UDP/IPv4; `socket(2, 1, 0)` = TCP/IPv4.
- `setsockopt` level `0xffff`/`SOL_SOCKET`, optname `4`/`SO_REUSEADDR`.
- `fcntl` GETFL(3)/SETFL(4) pair OR-ing in `0x80` (`O_NONBLOCK`).
- `bind()` with `addrlen == 0x10` (16) confirms a `sockaddr_in`.
- A fixed, non-well-known port with no apparent config/argv source.

## Seen in

- [sample-2026-08-mips-unknown](../../samples/sample-2026-08-mips-unknown/README.md)
  — port 54034 (`0xd312`, host byte order)
