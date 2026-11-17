# Bounded constant recovery (`dncil.analysis`)

Static recovery of a small, explicitly bounded class of expressions from CIL
method bodies that dncil has already parsed. The package is built for reverse
engineering work where a sample splits a suspicious string across constants and
array operations.

## Safety boundaries

The analysis is purely static and deliberately cannot execute code:

* it reads only dncil instruction objects and caller-supplied `Metadata` tables;
* it never loads an assembly, never touches the CLR loader and never resolves a
  token by executing metadata or a method;
* method tokens are interpreted only when the caller maps them to one of the
  whitelisted `KnownOp` operations; every other call is *unknown* and drives the
  affected state to pending;
* every `AnalysisBudget` limit aborts the run with a pending verdict.

Nothing is invented to make an answer look complete. In particular, an array
slot that was never written stays unknown and is never defaulted to NUL/zero.

## Supported expression class

* constant integers (`ldc.i4*`, `ldc.i8`) and constant strings (`ldstr`);
* local variable load/store (`ldloc*`, `stloc*`) and argument loads as unknown;
* finite arrays: `newarr` with a constant length, `ldlen`, `ldelem.*`,
  `stelem.*` with constant indices;
* char conversion: `conv.u2` (ECMA unsigned 16-bit wrap) and the whitelisted
  `System.Convert.ToChar(int)` / `ToChar(char)`;
* string construction: `System.String::.ctor(char[])` and
  `System.String.Concat` in the two-operand and params-array shapes;
* control flow: conditional/unconditional branches, `switch` and loops, handled
  with a chaotic-iteration worklist over a finite-height lattice until fixed
  point.

## When results are pending

A `RecoveredString` is reported certain only when every character and every join
is fully proven inside budget. Pending is returned, with reasons, when:

* an unknown method, unsupported opcode or unlisted token is encountered;
* two constants conflict at a control-flow join (both stay available as
  `alternatives`, never as a claimed runtime value);
* an array position is unwritten or dynamically indexed (`gap_count` reports it,
  `known_pieces` lists only proven fragments);
* an `AnalysisBudget` limit is reached.

`alternatives` and `known_pieces` are proven in isolation. They are candidates
for an analyst, not a claim that the program must produce that text at runtime.

## Metadata input

`ldstr` tokens and method tokens cannot be resolved from IL bytes alone. The
caller supplies plain dictionaries of integers to immutable data:

```python
from dncil.analysis import Metadata, MethodBinding, KnownOp, recover_strings

metadata = Metadata.from_tables(
    strings={0x70000001: "AB"},
    methods={0x06000001: MethodBinding(KnownOp.STRING_CTOR_CHARS,
                                       "System.String::.ctor(char[])")},
)
for record in recover_strings(method_body, metadata):
    print(record.certain, record.text, record.certainty_range,
          [(item.offset, item.mnemonic) for item in record.evidence])
```

Each certain record carries `evidence`: the offsets, mnemonics and raw bytes of
the instructions that produced it, so every recovered character is traceable to
concrete IL.
