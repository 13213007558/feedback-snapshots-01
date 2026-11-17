![dncil](./.github/dncil.png)

[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/dncil)](https://pypi.org/project/dncil)
[![Last release](https://img.shields.io/github/v/release/mandiant/dncil)](https://github.com/mandiant/dncil/releases)
[![CI](https://github.com/mandiant/dncil/actions/workflows/tests.yml/badge.svg)](https://github.com/mandiant/dncil/actions/workflows/tests.yml)
[![Downloads](https://pepy.tech/badge/dncil)](https://pepy.tech/project/dncil)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE.txt)

`dncil` is a Common Intermediate Language (`CIL`) disassembly library written in Python that supports parsing the header, instructions, and exception handlers of `.NET` managed methods. Parsed data is exposed through an object-oriented API to help you quickly develop `CIL` analysis tools using `dncil`.

Why `Python`? Existing libraries that support `CIL` disassembly, like [`dnLib`](https://github.com/0xd4d/dnlib), are written in `C#`. To leverage these tools, you must build `C#` applications which requires `C#` development experience. Using `dncil`, a pure `Python` alternative, you:

1. Do not need `C#` experience to analyze `CIL` programmatically.
2. Can quickly develop and test your `CIL` analysis tools.
3. Can easily integrate your `CIL` analysis tools with existing `Python` projects.

## Example

The example script [`print_cil_from_dn_file.py`](scripts/print_cil_from_dn_file.py) uses `dncil` together with `.NET` analysis library [`dnfile`](https://github.com/malwarefrank/dnfile) to disassemble the managed methods found in a `.NET` executable. Let's see what it can do.

First, we compile the following `C#` source code:

```C#
using System;	

public class HelloWorld
{
    public static void Main(string[] args)
    {
        Console.WriteLine ("Hello World!");
    }
}
```

Compilation results in a `PE` executable containing `.NET` metadata which informs the `Common Language Runtime` (`CLR`) how to execute our code. We use `dnfile` to parse this metadata which gives us the offset of our managed method `Main`. We then use `dncil` to disassemble and display the `CIL` instructions stored at this location.

Let's see the above in action:

```
$ python scripts/print_cil_from_dn_file.py hello-world.exe 

Method: Main
0000    00                  nop            
0001    72 01 00 00 70      ldstr          "Hello World!"
0006    28 04 00 00 0a      call           System.Console::WriteLine
000B    00                  nop            
000C    2a                  ret            
```

Our method `Main` is represented by the [`CilMethodBody`](dncil/cil/body/__init__.py) class. This class holds data that includes the header, `CIL` instructions, and exception handlers of a given managed method. It also exposes various helper functions:

```Python
>  main_method_body.flags
SmallFormat  :  false
TinyFormat   :  false
FatFormat    :  false
TinyFormat1  :  true
MoreSects    :  false
InitLocals   :  false
CompressedIL :  false
>  main_method_body.size
14
>  hexdump.hexdump(main_method_body.get_bytes())
00000000: 36 00 72 01 00 00 70 28  04 00 00 0A 00 2A        6.r...p(.....*
>  hexdump.hexdump(main_method_body.get_header_bytes())
00000000: 36                                                6
>  hexdump.hexdump(main_method_body.get_instruction_bytes())
00000000: 00 72 01 00 00 70 28 04  00 00 0A 00 2A           .r...p(.....*
```

Each `CIL` instruction found in our managed method `Main` is represented by the [`Instruction`](dncil/cil/instruction.py) class. This class holds data that includes the offset, mnemonic, opcode, and operand of a given `CIL` instruction. It also exposes various helper functions:

```Python
>  len(main_method_body.instructions)
5
>  insn = main_method_body.instructions[1]
>  insn.offset
1
>  insn.mnemonic
'ldstr'
>  insn.operand
token(0x70000001)
>  insn.is_ldstr()
True
>  insn.size
5
>  hexdump.hexdump(insn.get_bytes())
00000000: 72 01 00 00 70                                    r...p
>  hexdump.hexdump(insn.get_opcode_bytes())
00000000: 72                                                r
>  hexdump.hexdump(insn.get_operand_bytes())
00000000: 01 00 00 70                                       ...p
```

## Token evidence

An integer in IL is ambiguous on its own: the opcode decides whether it names a
string, method, field, or type. `dncil` exposes that context as a
[`TokenRequest`](dncil/clr/evidence.py) rather than letting a metadata backend
guess from the integer alone:

```Python
>  insn = main_method_body.instructions[2]
>  request = insn.get_token_request()
>  request
InlineMethod@0x0257 token(0xA000004)
>  request.kind
<TokenKind.InlineMethod: 'InlineMethod'>
>  request.offset
599
```

The kinds are `InlineTok`, `InlineMethod`, `InlineField`, `InlineType`,
`InlineString`, `InlineSig`, and `LocalVarSig`. Each kind declares the metadata
tables it accepts; `#US` string tokens are kept separate from metadata table
tokens. `CilMethodBody.get_token_requests()` returns requests for every
instruction plus the method header's local variable signature.

A [`TokenResolver`](dncil/clr/evidence.py) subclass performs lookups and returns
a `TokenResolution` that always keeps the original token, instruction offset, and
expected kind. Failures are structured `ResolutionIssue` values such as
`KIND_MISMATCH`, `INVALID_TABLE`, `MISSING_TABLE`, and `MISSING_ROW`; they are
never reported as a successfully resolved value. Cache entries are keyed by
`(kind, token value)`, so the same integer used as `InlineTok` and `InlineType`
gets separate lookups, and a cache hit still carries each use's own offset.

Core disassembly has no dependency on `dnfile`. When metadata interpretation is
needed, the optional [`dncil.dnfile`](dncil/dnfile/adapter.py) adapter reads a
method body through `dnfile` and resolves those requests:

```Python
import dnfile
from dncil.dnfile import DnfileTokenProvider, read_method_body, resolve_method_body

pe = dnfile.dnPE(path)
row = pe.net.mdtables.MethodDef.rows[0]
body = read_method_body(pe, row)
results = resolve_method_body(DnfileTokenProvider(pe), body)
```

`results` contains successful resolutions and unresolved references side by
side; `DnfileTokenProvider.report(body.get_token_requests())` groups the two.
The script [`print_cil_from_dn_file.py`](scripts/print_cil_from_dn_file.py) uses
this path, while [`print_cil_from_bytes.py`](scripts/print_cil_from_bytes.py)
continues to work with no metadata backend installed.

## Installing

To install `dncil` use `pip` to fetch the `dncil` module:

```
$ pip install dncil
```

To execute the example scripts be sure to install [`dnfile`](https://github.com/malwarefrank/dnfile). Alternatively, install `dncil` with the development dependencies as described in the `Development` section below.

See [print_cil_from_bytes.py](scripts/print_cil_from_bytes.py) for a quick example of using `dncil`to print the `CIL` instructions found in a byte stream containing a `.NET` managed method.

## Development

If you'd like to review and modify `dncil` source code, you'll need to download it from GitHub and install it locally. 

Use the following command to install `dncil` locally with development dependencies:

```
$ pip install /local/path/to/src[dev]
```

You'll need `dncil`'s development dependencies to run tests and linting as described below.

### Testing

Use the following command to run tests:

```
$ pytest /local/path/to/src/tests
```

### Linting

Use the following commands to identify format errors:

```
$ black -l 120 -c /local/path/to/src
$ isort --profile black --length-sort --line-width 120 -c /local/path/to/src
$ mypy --config-file /local/path/to/src/.github/mypy/mypy.ini /local/path/to/src/dncil/ /local/path/to/src/scripts/ /local/path/to/src/tests/
```

## Credits

`dncil` is based on the `CIL` parsing code found in [`dnLib`](https://github.com/0xd4d/dnlib).
