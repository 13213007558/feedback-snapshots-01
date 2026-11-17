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

## Installing

To install `dncil` use `pip` to fetch the `dncil` module:

```
$ pip install dncil
```

To execute the example scripts be sure to install [`dnfile`](https://github.com/malwarefrank/dnfile). Alternatively, install `dncil` with the development dependencies as described in the `Development` section below.

See [print_cil_from_bytes.py](scripts/print_cil_from_bytes.py) for a quick example of using `dncil`to print the `CIL` instructions found in a byte stream containing a `.NET` managed method.

## Entry-Point Review

`dncil.analysis` adds a bounded, metadata-driven review for managed plugin entry points. It disassembles only the method bodies it can reach from a given entry point and never loads, reflects over, or executes the assembly.

The review follows calls whose target is determinable from this assembly's metadata:

- `call` / `newobj` into a `MethodDef` row in the same module, including helper methods several calls deep.
- `MemberRef` rows whose parent is a `ModuleRef`, which is how P/Invoke declarations are referenced. A reachable P/Invoke is reported as a rejecting finding with every caller token, call offset, and operand token on the path.

It deliberately stops and records an unresolved call site instead of guessing when the target is a `callvirt` (an override may change the target), a `calli` or a function pointer (`ldftn` / `ldvirtftn`), a generic `MethodSpec` or generic method body, an abstract method, or a target in another assembly. Reachable pointer-memory instructions (`ldind.*`, `stind.*`, `localloc`, `cpblk`, `initblk`, `mkrefany`, `refanyval`) are reported for manual review.

The result is one of `reject`, `manual_review`, or `no_reachable_finding`. A method that is never reached from the entry point is not reported: static reachability is not the same as proving the entry point reaches it. A clean result is also not proof that the CLR sandbox or the plugin is safe; it only means this bounded review found no reachable signal.

```Python
import dnfile
from dncil.analysis.dnfile_adapter import DnfileMetadataView
from dncil.analysis.review import review_entry_points

pe = dnfile.dnPE("plugin.dll")
report = review_entry_points(DnfileMetadataView(pe))
print(report.format_text())
```

Use `scripts/review_dotnet_entry.py` for the same review from the command line. It exits `0` for no reachable finding, `1` for manual review, and `2` for reject, and accepts repeated `--entry 0x06000001` tokens to review specific methods instead of the declared entry point.

```bash
$ python scripts/review_dotnet_entry.py plugin.dll
```

`dncil.analysis.metadata.SyntheticMetadata` implements the same `MetadataView` interface for callers that already hold IL bytes and metadata facts, so the walker can be used without a PE.

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
