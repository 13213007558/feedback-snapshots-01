This directory contains a number of example command line apps using PyFilesystem.

They are intended to be a learning aid and not exactly finished products, but all these examples are completely functional.

- count_py.py    Display how much storage is used in your Python files.
- find_dups.py   Locate duplicate files.
- rm_pyc.py      Remove compiled Python files.
- upload.py      Upload files to a filesystem.
- mount_swap_mid_copy.py
                 Hot-swap one MountFS mount in the middle of a copy, while
                 old read/write handles keep draining against the old space,
                 new requests resolve to the new space, and other mounts
                 keep working. Prints an audit table and checks every
                 security invariant. Run from the repository root:

                     python examples/mount_swap_mid_copy.py
