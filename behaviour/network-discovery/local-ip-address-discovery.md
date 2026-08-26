# Local IPv4 Address Discovery via Connected Socket

**Category:** Network Discovery
**Confidence:** High — the socket target and `getsockname()` usage identify the local address selected for an outbound route. The exact returned value depends on error handling and the host routing table.

## What it does

This routine creates an IPv4 stream socket, attempts to connect to
`8.8.8.8:53`, and then asks the kernel for the socket's local endpoint.
The returned address is the machine's locally assigned IPv4 address for
that route, usually the private interface address (for example,
`192.168.1.20`), not the public address assigned by NAT.

The `connect()` call is used to make the kernel select the appropriate
outbound interface. No application data needs to be sent for this
purpose. Because this sample uses `SOCK_STREAM`, it may also generate a
real TCP connection attempt; the return value is ignored.

## What it looks like in code

```c
uint32_t util_local_addr(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in remote = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(0x08080808), // 8.8.8.8
    };
    struct sockaddr_in local;
    socklen_t length = sizeof(local);

    if (fd != -1) {
        connect(fd, (struct sockaddr *)&remote, sizeof(remote));
        getsockname(fd, (struct sockaddr *)&local, &length);
        close(fd);
    }
    return local.sin_addr.s_addr;
}
```

Decompiler output may flatten `sockaddr_in` fields into `sa_data` byte
offsets. Here, `2` is `AF_INET`, `1` is `SOCK_STREAM`, `0x8080808` is
`8.8.8.8`, and `0x35` is port 53 after `htons()`.

## Why malware does it

Malware can use the address as host metadata in an initial registration
or beacon, select an appropriate C2 route, or distinguish networked
hosts from isolated sandboxes. In Mirai, `LOCAL_ADDR` is collected before
C2 setup and again after a C2 connection, making host identification a
credible use; the surrounding code is needed to determine exactly how
the value is serialized or used.

This is not, by itself, public-IP discovery. A public address generally
requires an external service to observe the NAT mapping. It is also not
necessarily malicious: ordinary software uses the same socket idiom to
select a source interface.

## How to recognize it

- `socket(AF_INET, SOCK_STREAM, 0)` or an equivalent IPv4 socket setup.
- A `connect()` to a fixed, reachable external address, commonly a public DNS or web endpoint.
- `getsockname()` on the same socket, followed by extraction of `sin_addr`.
- The result passed into a beacon, registration packet, host identifier, or C2 handshake.
- Missing or ignored return-value checks, which may leave the result invalid when the route or connection fails.

## MITRE ATT&CK

- **[T1016.001 — Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001/):** Directly relevant when the external connection is used to determine whether the host has Internet access or which local address is used for Internet egress.
- **[T1016 — System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016/):** A broader fallback mapping when the code is documented as collecting the host's local network address but the Internet-connectivity purpose is not established.

Do not map this function to C2 merely because it contacts `8.8.8.8`; map C2 only from the surrounding data flow or protocol behavior.

## Seen in

- [Mirai sample walkthrough](../../samples/mirai.md) — the local sample records `util_local_addr()` during startup and after C2 connection. The public Mirai source likewise assigns its result to `LOCAL_ADDR` before C2 setup and logs/sends related state during connection handling ([`main.c`](https://github.com/jgamblin/Mirai-Source-Code/blob/master/mirai/bot/main.c)).
- [ShellShock malware analysis](https://m00dy.github.io/An-Analysis-of-Shell-shock-malware/) — reports malware using `getsockname()` to obtain the host IP, alongside `/proc/net/route` and MAC-address discovery. The implementation differs, so treat this as a related example rather than an exact code match.

## Open questions

- Is `connect()` successful on the target device, and does the call trigger observable TCP traffic?
- Is `local_28.sa_data._2_4_` definitely the `sin_addr` field after reconstructing the structure layout and endianness?
- Where is the returned value consumed: C2 registration, bot identity, routing, or a sandbox/network check?
- What happens when `socket()`, `connect()`, or `getsockname()` fails? The decompiled routine appears not to initialize or validate every failure path.
