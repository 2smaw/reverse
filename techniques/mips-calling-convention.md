# MIPS Calling Convention & Disassembly Notes

Quick reference for reading MIPS disassembly (used e.g. in embedded/
IoT-targeted binaries), since it differs from x86/ARM in a few ways
that trip up beginners.

## Registers

| Register | Role |
|---|---|
| `a0`-`a3` | first four function arguments |
| `v0` | return value |
| `t9` | by convention holds the target function address for an indirect call via `jalr` |
| `gp` | global pointer — base for GOT-relative addressing of globals/imports |
| `sp` | stack pointer; `local_XX(sp)` are stack slots |

## The delay slot rule

The instruction immediately after a branch or jump **always executes**,
whether or not the branch is taken. This is architectural (MIPS
pipeline design), not a bug or decompiler artifact. Always check what's
sitting in the delay slot — it's frequently doing real work (e.g.
setting up a call argument, or computing a value used regardless of
which branch is taken), not a no-op.

Example seen in practice:
```
bne  v0, zero, LAB_xxxx      ; branch if strchr() found a match
_subu a2, v0, a0              ; delay slot: ALWAYS runs, computes
                               ; len = dot - domain regardless of
                               ; whether the branch is taken
```

## Recognizing an indirect call to a known library function

```
lw   t9, -0x7db8(gp) => ->strchr    ; resolve strchr's address via GOT
sw   a0, local_38(sp)                ; spill: back up an argument
jalr t9 => strchr                    ; call
_li  a1, 0x2e                        ; delay slot: sets 2nd arg ('.')
```

The `=> ->funcname` / `=> funcname` annotations (as shown by some
decompilers/disassemblers) indicate the tool has resolved a GOT slot or
recognized a known library routine — trust these once confirmed, they
save you from re-deriving well-known libc behavior from scratch.

## Spill/reload pattern

```
sw   a0, local_38(sp)   ; spill before call (callee may clobber a0)
jalr t9 => somefunc
...
lw   a0, local_38(sp)   ; reload after call
```

Two decompiler-named variables that are a spill/reload pair of the same
value should usually be treated (and eventually renamed) as one logical
variable, even though the decompiler shows them as separate locals.

## The `or reg, reg, zero` move idiom

MIPS has no dedicated "move" instruction; `or t0, v0, zero` is the
standard idiom for `t0 = v0`. Recognize this as a plain assignment, not
a bitwise operation of interest.
